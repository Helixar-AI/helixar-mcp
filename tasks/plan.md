# Implementation Plan: helixar-mcp Claude Connector

## Overview

The repo at `/Users/siri/helixar-mcp` (remote: `Helixar-AI/helixar-mcp`) is a remote MCP server that exposes Helixar's agentic-AI security tools natively inside Claude.ai, Claude Desktop, and Cowork:

- **`helixar_inspect_mcp`** — Sentinel scanner, viral free tier.
- **`helixar_hdp_validate`** — HDP delegation chain validator, IETF citation lever.
- **`helixar_releaseguard`** _(Phase 4-v2, planned)_ — MCP wrapper around [`Helixar-AI/ReleaseGuard`](https://github.com/Helixar-AI/ReleaseGuard), the open-source artifact policy engine. Replaces the revoked `helixar_triage_alert` (see Phase 4 note below).

Source spec is `~/Documents/helixar-claude-connector-plan.docx` (extracted to `/tmp/connector-plan.txt`). The plan there is a 7-week schedule with four phases (A — Foundation, B — Core tools + OAuth, C — Pilot demo + submission prep, D — Submission + launch). This implementation plan re-slices that schedule into vertical, demo-able tasks the agent can build incrementally without losing the strategic intent.

## Architecture decisions (locked from spec)

- **Language:** TypeScript, ESM, NodeNext module resolution, strict mode.
- **MCP SDK:** `@modelcontextprotocol/sdk` (official Anthropic). Tool registration via `Server.setRequestHandler` for `tools/list` + `tools/call`.
- **Transport v1:** stdio for local Claude Desktop / dev. Streamable HTTP via Cloudflare Workers comes later (`src/worker.ts`).
- **Validation:** Zod for all tool input schemas — runtime safety, mirrors the JSON schema MCP exposes.
- **Narration:** Anthropic SDK (`@anthropic-ai/sdk`) when `ANTHROPIC_API_KEY` is set, else a deterministic fallback string built from the structured findings. Per spec §9, never let a Claude rate limit break a tool call.
- **Auth tiers:**
  - **Quick / public** — `inspect_mcp` (top-8 rules), `hdp_validate`. No auth, ever.
  - **Authenticated** — `inspect_mcp` deep mode (26 rules), `triage_alert`. Requires `api_key` arg or OAuth. OAuth flow is Phase B-late and deferred from this session.
- **IP protection (spec §6):** Hunch Mode internals, IOB pipeline weights, sensor implementation, FP rates, exact thresholds — **never** reach the codebase. Public rules describe categories and indicators only. Severity capped at High in `triage_alert`. The `is_hunch_detection` flag is a boolean, no further detail.

## Dependency graph

```
Foundation
    │  (package.json, tsconfig, vitest, .gitignore, LICENSE, README, CI workflow)
    │
    ├── lib/narrate.ts ─────────────────────────────────────┐
    │   (Anthropic call w/ deterministic fallback)          │
    │                                                       │
    ├── Tool 1 vertical slice — helixar_inspect_mcp         │
    │     lib/sentinel-rules.ts (top-8 quick first,         │ <─ uses
    │       then 18 more for deep) ──→                      │
    │     tools/inspect-mcp.ts (parse → rules → score → ────┤
    │       narrate)                                        │
    │     tests for both                                    │
    │                                                       │
    ├── Tool 2 vertical slice — helixar_hdp_validate        │
    │     lib/hdp-schema.ts (types + 9 validation rules) ───┤
    │     tools/hdp-validate.ts (validator + draft+DOI ─────┤
    │       always emitted)                                 │
    │     tests                                             │
    │                                                       │
    ├── Tool 3 vertical slice — helixar_triage_alert        │
    │     lib/vigil-parser.ts (normalize + stage classify) ─┤
    │     tools/triage-alert.ts (3 output formats, ─────────┘
    │       severity capped at High)
    │     tests
    │
    ├── server.ts (MCP stdio entrypoint registering all 3)
    │
    └── (deferred to next sessions)
        ├── src/worker.ts — CF Workers Streamable HTTP adapter
        ├── OAuth 2.0 + Dynamic Client Registration server
        ├── manifest.json + helixar.ai/connect landing page
        ├── platform.claude.com/plugins/submit submission
        └── Self-scan with Sentinel deep + remediation
```

Foundation gates everything. `lib/narrate.ts` is shared by all three tools — must land before any tool can ship its narrative output. Each of the three tool slices is independent of the others (different libs, different tests) — they parallelise after `narrate.ts`. The MCP `server.ts` glue is small and lands last because it just registers whatever tools are ready.

## Vertical-slice tasks

Each task delivers a complete user-visible capability — the rule library, the tool implementation, the Zod schema, the tests, and (where applicable) the MCP registration entry. Horizontal layers (e.g. "implement all 26 rules first, then write the tool") are explicitly avoided.

---

### Phase 1 — Foundation

#### Task 1: Scaffold the TypeScript project

**Description.** Stand up the repo with the toolchain that everything else depends on. Strict TypeScript ESM, vitest, eslint, MCP SDK + Zod + Anthropic SDK installed. Add `.gitignore`, `LICENSE` (MIT — repo will be open-source per spec §7 launch strategy), `README.md` placeholder, and the GitHub Actions CI workflow that runs typecheck + test on every PR.

**Acceptance criteria:**
- [ ] `package.json` declares ESM (`"type": "module"`), Node 20+ engines, scripts `build`, `typecheck`, `test`, `lint`, `start`.
- [ ] `tsconfig.json` with `strict`, `module: NodeNext`, `target: ES2022`, source maps, `outDir: dist`.
- [ ] `vitest.config.ts` configured for ESM, `coverage` provider available.
- [ ] `.gitignore` covers `node_modules/`, `dist/`, `.env`, `coverage/`, `.vscode/`.
- [ ] `LICENSE` (MIT) + minimal `README.md` describing the three tools.
- [ ] `.github/workflows/ci.yml` runs `npm ci && npm run typecheck && npm test` on push + PR.
- [ ] `npm install && npm run typecheck && npm test` succeeds locally with zero source files (empty test suite is OK).

**Verification:**
- [ ] `npm run typecheck` exits 0 on a fresh clone.
- [ ] `npm test` exits 0.
- [ ] CI workflow YAML lints (no syntax errors in GH Actions schema).

**Dependencies:** none.
**Files touched:** `package.json`, `tsconfig.json`, `vitest.config.ts`, `.gitignore`, `LICENSE`, `README.md`, `.github/workflows/ci.yml`.
**Scope:** S.

---

#### Task 2: `lib/narrate.ts` — Anthropic call with deterministic fallback

**Description.** Single helper used by all three tools. Signature: `narrate(prompt: string, options?: { audience?, maxTokens? }): Promise<string>`. If `ANTHROPIC_API_KEY` is set in env, call `client.messages.create({ model: "claude-haiku-4-5", … })`. Otherwise return a deterministic fallback string built from the prompt's structured input. Never throws on API failure — fallback is always safe.

**Acceptance criteria:**
- [ ] Exports a single `narrate(prompt, options?)` function.
- [ ] Uses `claude-haiku-4-5` by default (fast, cheap, sufficient for 3-4 sentence summaries).
- [ ] When `ANTHROPIC_API_KEY` is unset, returns a deterministic fallback formatted from the prompt with no network call.
- [ ] When the SDK throws (rate limit, network, 5xx) the function logs once at warn and returns the fallback.
- [ ] The fallback is recognisable — every fallback string starts with `[fallback]` so callers (and tests) can tell.

**Verification:**
- [ ] Unit test: with `ANTHROPIC_API_KEY` unset, returns a string starting with `[fallback]`.
- [ ] Unit test: simulated SDK throw still returns a `[fallback]` string (no exception escapes).
- [ ] Manual smoke (optional, only if env set): with a real key, returns a non-fallback string.

**Dependencies:** Task 1.
**Files:** `src/lib/narrate.ts`, `tests/lib/narrate.test.ts`.
**Scope:** S.

---

### Checkpoint A — Foundation

- [ ] `npm install`, `npm run typecheck`, `npm test` all green.
- [ ] `narrate()` works in fallback mode.
- [ ] Directory layout matches the dependency graph (above).
- [ ] **Commit + tag `v0.0.1-foundation`**.

---

### Phase 2 — Tool 1: `helixar_inspect_mcp` (quick mode first)

#### Task 3: `lib/sentinel-rules.ts` — top-8 quick-mode rules

**Description.** The 8 rules that ship in quick / authless mode. Each rule is a typed object with `id` (e.g. `S-001`), `severity` (`low`/`medium`/`high`/`critical`), `category` (`authentication`/`authorization`/`data_exfiltration`/`injection`/`supply_chain`/`behavioral`), `description`, `remediation`, and `check(manifest): { triggered: boolean, evidence?: string }`. Public-safe descriptions only — no implementation thresholds, no sequence patterns (per spec §6).

Top-8 (per spec §3 Tool 1, the rows marked `Quick + Deep`):
- `S-001`–`S-003` Authentication — no auth, broad OAuth scopes, no TLS
- `S-004` Authorization — destructive tools without confirmation
- `S-007`–`S-008` Data exfiltration — unbounded export, PII exposure
- `S-010` Injection — prompt injection in tool descriptions
- `S-017` Behavioral — no rate limiting

**Acceptance criteria:**
- [ ] `SENTINEL_QUICK_RULES: SentinelRule[]` of length exactly 8.
- [ ] Every rule has all required fields populated.
- [ ] `check()` runs against an `MCPManifest` shape (Zod-typed in same file): `{ name, version, tools[]: { name, description, parameters? }, transport?, auth? }`.
- [ ] Each rule has at least one positive (triggered) and one negative (clean) fixture in tests.
- [ ] `applyRules(manifest, ruleSet)` runs every rule and returns `RuleFinding[]`.

**Verification:**
- [ ] 8 rules × 2 fixtures = 16 individual rule tests pass.
- [ ] `applyRules({…clean manifest}, SENTINEL_QUICK_RULES)` returns `[]`.
- [ ] `applyRules({…unsafe manifest with no auth + PII tool}, SENTINEL_QUICK_RULES)` returns ≥ 2 findings.

**Dependencies:** Task 1.
**Files:** `src/lib/sentinel-rules.ts`, `tests/lib/sentinel-rules.test.ts`.
**Scope:** M.

---

#### Task 4: `tools/inspect-mcp.ts` — `helixar_inspect_mcp` (quick mode end-to-end)

**Description.** The actual tool exposed via MCP. Input: `target` (URL string or raw manifest JSON), `mode: "quick" | "deep"` (default quick), `context?`, `api_key?` (only required for deep — Phase 5). Steps: parse target → fetch if URL → JSON-parse → run `applyRules` → score `risk_score` weighted by severity → bucket `risk_level` → call `narrate()` for summary → detect agentic chaining patterns for `hdp_recommendation`. Return JSON matching the spec output schema.

**Acceptance criteria:**
- [ ] Zod input schema with `target` required, `mode` defaulting to `quick`.
- [ ] Quick mode never requires `api_key` (returns 401-equivalent error if deep mode requested without key — Phase 5 will resolve).
- [ ] Risk score: critical=40, high=20, medium=10, low=5 weights, capped at 100.
- [ ] Risk level buckets: 0=NONE, 1-19=LOW, 20-49=MED, 50-79=HIGH, 80+=CRIT.
- [ ] `hdp_recommendation` true when manifest has ≥2 tools with autonomous behaviour or chaining hints (e.g. tool name contains `delegate` / `chain` / `forward` / `relay`).
- [ ] Output shape exactly matches spec § Tool 1 Output Schema.

**Verification:**
- [ ] Unit test: clean manifest → score 0, level NONE, no findings, `hdp_recommendation: false`.
- [ ] Unit test: unsafe manifest (no auth + destructive write tool + no rate limit) → ≥ 3 findings, risk_level ≥ MED.
- [ ] Unit test: `mode: "deep"` without `api_key` → returns structured error rather than throwing.
- [ ] Unit test: manifest with `chain_*` tools → `hdp_recommendation: true`.
- [ ] Narrative is a string; in fallback mode it starts with `[fallback]`.

**Dependencies:** Tasks 1, 2, 3.
**Files:** `src/tools/inspect-mcp.ts`, `tests/tools/inspect-mcp.test.ts`.
**Scope:** M.

---

### Checkpoint B — Tool 1 quick-mode shippable

- [ ] `helixar_inspect_mcp` works end-to-end against a sample manifest.
- [ ] All quick-mode tests green.
- [ ] **Commit + tag `v0.1.0-tool1-quick`**.

---

### Phase 3 — Tool 2: `helixar_hdp_validate`

#### Task 5: `lib/hdp-schema.ts` — chain types + 9 validation rules

**Description.** Zod-typed schemas for an HDP chain: `root_principal`, `hops[]` (each: `delegator`, `delegatee`, `scope[]`, `expires_at`, `signature?`, `purpose?`). Validation engine returns `Violation[]`. The 9 rules per spec §3 Tool 2:

| ID | Severity | Section | Rule |
|---|---|---|---|
| HDP-ROOT-001 | HIGH | §3.1 | Missing `root_principal` |
| HDP-SCOPE-001 | HIGH | §4.1 | No scope on hop = unlimited delegation |
| HDP-SCOPE-002 | CRITICAL | §4.2 | Scope escalation — delegatee scope ⊄ delegator scope |
| HDP-TTL-001 | HIGH | §5.1 | Hop expired |
| HDP-SIG-001 | MEDIUM | §6.1 | Unsigned hop |
| HDP-HOPS-001 | MEDIUM | §4.3 | Chain depth > 5 |
| HDP-HOPS-002 | CRITICAL | §4.3 | `max_hops` budget exhausted |
| HDP-HOP-003 | HIGH | §3.4 | Self-delegation (delegator == delegatee) |
| HDP-PURPOSE-001 | LOW | §3.5 | Missing `purpose` |

**Acceptance criteria:**
- [ ] `HDPChain` Zod schema parses valid + rejects invalid shapes.
- [ ] `validateChain(chain): Violation[]` runs all 9 rules.
- [ ] Each rule emits a `Violation { rule_id, severity, hop_index, section, message, evidence? }`.
- [ ] Scope-escalation detection is set-based and correct (subset check, including wildcard handling — `*` means "everything").
- [ ] Empty `hops[]` is a valid (no-op) chain — emits no violations on its own.

**Verification:**
- [ ] Test fixtures: clean 2-hop chain (no violations); chain with scope escalation (HDP-SCOPE-002 fires); chain with 6 hops (HDP-HOPS-001 fires); chain with self-delegation; chain with expired hop.
- [ ] `scope_escalation_detected` derived correctly from rule output.
- [ ] All severity values are one of `low | medium | high | critical`.

**Dependencies:** Task 1.
**Files:** `src/lib/hdp-schema.ts`, `tests/lib/hdp-schema.test.ts`.
**Scope:** M.

---

#### Task 6: `tools/hdp-validate.ts` — `helixar_hdp_validate` end-to-end

**Description.** MCP tool. Input: HDP `chain` object plus optional `strict: boolean`. Runs `validateChain`, computes `valid` (no CRITICAL/HIGH if not strict; zero violations if strict), per-hop summary (status/delegator/delegatee/scope), `scope_escalation_detected` boolean, narrative via `narrate()`. **Always** appends `draft_reference: "draft-helixar-hdp-agentic-delegation-00"` and `doi: "10.5281/zenodo.19332023"` to every output (per spec §3 Tool 2 — protocol-citation lever).

**Acceptance criteria:**
- [ ] Zod input schema validates `chain` shape strictly.
- [ ] `valid` true when no CRITICAL/HIGH; false otherwise. With `strict: true`, false on any violation.
- [ ] `hops[]` summarises every hop with `status: "valid" | "warning" | "violation"` (warning = MEDIUM/LOW only; violation = HIGH/CRITICAL).
- [ ] `scope_escalation_detected` true iff any HDP-SCOPE-002 violation present.
- [ ] `draft_reference` and `doi` fields **always** present, exact strings per spec.
- [ ] Narrative is a string; in fallback mode starts with `[fallback]`.

**Verification:**
- [ ] Clean chain → `valid: true`, no violations, `draft_reference` + `doi` set.
- [ ] Scope-escalation chain → `valid: false`, `scope_escalation_detected: true`.
- [ ] Empty chain still emits `draft_reference` + `doi`.
- [ ] Strict mode flips `valid` to false on any LOW/MEDIUM-only chain.

**Dependencies:** Tasks 1, 2, 5.
**Files:** `src/tools/hdp-validate.ts`, `tests/tools/hdp-validate.test.ts`.
**Scope:** S.

---

### Checkpoint C — Tool 2 shippable

- [ ] `helixar_hdp_validate` works end-to-end.
- [ ] Every output emits the IETF draft + DOI strings (verified by test).
- [ ] **Commit + tag `v0.2.0-tool2-hdp`**.

---

### Phase 4 — Tool 3: `helixar_triage_alert` — **REVOKED (v0.4.1)**

> **Revoked.** Even with the IP-protection guard, exposing a kill-chain stage classifier and Vigil payload normaliser publicly widens the attack surface too far. Tasks 7–8 below describe the original design for historical context only — the code and tests were removed in `v0.4.1-revoke-triage` and the slot is taken by Phase 4-v2 (`helixar_releaseguard`).

#### Task 7: `lib/vigil-parser.ts` — payload normaliser + kill-chain stage classifier

**Description.** Accept a Vigil/ATP detection payload (loose JSON; the customer's payloads vary). Normalise to `NormalizedAlert { alert_id, agent_id, severity, indicators[], timeline?, raw_signals?, … }`. Classify into one of four stages: `Preparation` / `Positioning` / `Expansion` / `Objective` (spec §3 Tool 3 stage table). **Severity is hard-capped at `high`** — even a `critical` input becomes `high` on output (spec §3 Tool 3, no autonomous enforcement on unvalidated detections). Surface `is_hunch_detection` boolean only — no further Hunch internals.

**Acceptance criteria:**
- [ ] `parseAlert(payload): NormalizedAlert` accepts loose JSON, never throws on missing optional fields.
- [ ] `classifyStage(alert): 'Preparation' | 'Positioning' | 'Expansion' | 'Objective'` based on indicator keywords (recon → Preparation, persistence/lateral → Positioning, escalation/pivot → Expansion, exfil/impact → Objective).
- [ ] `cappedSeverity(input): 'low' | 'medium' | 'high'` — `critical` → `high`.
- [ ] `is_hunch_detection` boolean derived from input field `detector_kind === 'hunch'` or similar; default false.
- [ ] No symbol named anything resembling `IOB`, `pipeline`, `weight`, `signal_score`, etc. exists in the file (IP protection guard).

**Verification:**
- [ ] Test fixture per stage (4 fixtures) + a `critical`-input test that asserts severity capped to `high` + a hunch-payload test for `is_hunch_detection: true`.
- [ ] Source file passes a regex grep for forbidden symbols (executed as part of the test).

**Dependencies:** Task 1.
**Files:** `src/lib/vigil-parser.ts`, `tests/lib/vigil-parser.test.ts`.
**Scope:** M.

---

#### Task 8: `tools/triage-alert.ts` — `helixar_triage_alert` end-to-end with three formats

**Description.** MCP tool. Input: `payload` (the raw alert), `format: "executive" | "technical" | "brief"` (default `technical`). Pipeline: `parseAlert` → `classifyStage` → `cappedSeverity` → `narrate()` with format-specific prompt template. Output: `{ alert_id, stage, severity, narrative, recommended_action, is_hunch_detection, vigil_tier_reference }`. `vigil_tier_reference` is a const map exposing tier 0-4 labels (Observe/Alert/Throttle/Isolate/Kill) — public-safe per spec §6.

**Acceptance criteria:**
- [ ] Zod input schema validates `payload` (loose object) and `format` enum.
- [ ] Three format prompt templates exist, distinct, each ≤ 5 sentence target.
- [ ] Output is identical shape regardless of format (only narrative text differs).
- [ ] `severity` never returns `critical` even if input said critical.
- [ ] `vigil_tier_reference` is included on every output, structurally identical.
- [ ] `is_hunch_detection` propagated from parser.

**Verification:**
- [ ] `format: "brief"` → narrative ≤ ~250 chars.
- [ ] `format: "executive"` narrative does not contain technical jargon (a small denylist test: `[CVE`, `auid=`, `pid=`, `hash:`).
- [ ] `format: "technical"` narrative is allowed to contain those technical tokens.
- [ ] Critical-input alert → `severity: "high"`.

**Dependencies:** Tasks 1, 2, 7.
**Files:** `src/tools/triage-alert.ts`, `tests/tools/triage-alert.test.ts`.
**Scope:** M.

---

### Checkpoint D — Tool 3 shippable — **REVOKED**

- [x] ~~`helixar_triage_alert` works end-to-end across all three formats.~~ _(revoked v0.4.1)_
- [x] ~~IP-protection guard (forbidden-symbol grep) green.~~ _(files deleted)_
- [x] ~~**Commit + tag `v0.3.0-tool3-triage`**.~~ _(tag retained as archaeology; not re-pointed)_

---

### Phase 4-v2 — Tool 3 (replacement): `helixar_releaseguard`

Wraps [`Helixar-AI/ReleaseGuard`](https://github.com/Helixar-AI/ReleaseGuard) — already open-source, Go-based artifact policy engine. Because the underlying engine is public, the MCP tool can expose much more surface without leaking Helixar IP: rule categories, commands, and output formats all live in the ReleaseGuard repo already.

**Tier split (matches `inspect_mcp`):**
- **Quick / public (authless)** — `releaseguard check`: scan an artifact or repo target for secrets, metadata leaks, license gaps, forbidden files. Report-only, no writes.
- **Deep (auth-gated)** — the full `harden` pipeline (`fix` + `obfuscate` + `sign` + `attest`, plus SBOM generation). Requires `api_key` (any non-empty string for v1, real OAuth in Phase 7).

**Architecture decision — execution model:** the MCP tool shells out to a local `releaseguard` binary (documented as a system dependency in the README). A future variant can proxy to a ReleaseGuard Cloud API when that endpoint is public. Either way the MCP tool itself is a thin normaliser → CLI invocation → JSON parse → `narrate()` wrapper, with no ReleaseGuard logic re-implemented in TypeScript.

#### Task 7-v2: `lib/releaseguard-runner.ts` — CLI adapter

**Description.** Shell out to the `releaseguard` binary. Signature: `runReleaseGuard(target: string, command: "check" | "fix" | "harden" | "sbom", options: { format?: "json" | "sarif"; config?: string }): Promise<RunResult>`. Uses `child_process.spawn` with `--format json` and captures stdout/stderr. Returns `{ ok: boolean; findings: ReleaseGuardFinding[]; raw: unknown; stderr: string }`. Missing-binary case returns a structured `{ ok: false, reason: "binary_missing" }` instead of throwing.

**Acceptance criteria:**
- [ ] Adapter never throws — all failure modes returned as structured results.
- [ ] Handles binary-missing, non-zero exit, malformed-JSON output paths distinctly.
- [ ] `ReleaseGuardFinding` type mirrors the CLI's JSON shape (rule id, severity, category, path, evidence) — derived from the ReleaseGuard repo's `--format json` output.
- [ ] No ReleaseGuard rules are re-implemented; this file only normalises the CLI's output into our `RuleFinding` shape.

**Verification:**
- [ ] Unit test with a mocked `spawn` that returns a fixture JSON → parses into `findings[]`.
- [ ] Unit test: missing binary → `{ ok: false, reason: "binary_missing" }`.
- [ ] Unit test: exit != 0 with warnings-only output → `ok: true` with findings (CLI uses exit codes for policy gates, not for tool errors).

**Dependencies:** Task 1.
**Files:** `src/lib/releaseguard-runner.ts`, `tests/lib/releaseguard-runner.test.ts`.
**Scope:** M.

---

#### Task 8-v2: `tools/releaseguard.ts` — `helixar_releaseguard` end-to-end

**Description.** MCP tool. Input: `target` (filesystem path or git repo URL), `mode: "quick" | "deep"` (default `quick`), `command?: "check" | "fix" | "harden" | "sbom"`, `format?: "brief" | "technical" | "executive"`, `api_key?`. Quick mode is locked to `command: "check"` regardless of input. Deep mode allows the full command set and requires `api_key`.

Output shape mirrors `inspect_mcp`: `{ risk_score, risk_level, findings[], summary, artifact_ref?, sbom_ref? }`. `artifact_ref` and `sbom_ref` populated only by deep-mode `harden`/`sbom` runs.

**Acceptance criteria:**
- [ ] Zod input schema. `target` required; `mode` defaults to `quick`.
- [ ] Quick mode + any `command` → coerced to `check`. Never writes to the target.
- [ ] Deep mode without `api_key` → structured `{ error: "auth_required", message: … }` (same shape as `inspect_mcp`).
- [ ] Binary-missing → structured `{ error: "dependency_missing", message: "releaseguard CLI not found; install via https://github.com/Helixar-AI/ReleaseGuard" }`.
- [ ] Severity → score weights match `inspect_mcp` (crit=40, high=20, med=10, low=5, cap 100); same `risk_level` buckets.
- [ ] `summary` is a string; fallback narratives start with `[fallback]`.

**Verification:**
- [ ] Unit test: quick mode + clean fixture JSON → `risk_level: "NONE"`, `command` forced to `check`.
- [ ] Unit test: deep mode w/o api_key → `auth_required`.
- [ ] Unit test: binary-missing path → `dependency_missing`.
- [ ] Unit test: deep mode + api_key + `harden` → output includes `artifact_ref`.
- [ ] Self-scan integration test (optional, skipped in CI when binary absent): `target: "./"` → findings array populated.

**Dependencies:** Tasks 1, 2, 7-v2.
**Files:** `src/tools/releaseguard.ts`, `tests/tools/releaseguard.test.ts`.
**Scope:** M.

---

#### Task 8.5-v2: Register `helixar_releaseguard` in `server.ts`

**Description.** Add the descriptor + dispatch case. Total registered tools returns to 3.

**Acceptance criteria:**
- [ ] `TOOL_DESCRIPTORS` length = 3.
- [ ] `dispatchTool("helixar_releaseguard", ...)` routes correctly.
- [ ] Existing `server.test.ts` updated: expected name list → `[hdp_validate, inspect_mcp, releaseguard]`.

**Dependencies:** Task 8-v2.
**Files:** `src/server.ts`, `tests/server.test.ts`.
**Scope:** S.

---

### Checkpoint D-v2 — Tool 3 (ReleaseGuard) shippable

- [ ] `helixar_releaseguard` works end-to-end (quick + deep).
- [ ] Binary-missing path returns a structured error.
- [ ] Tool registered in `server.ts`; registry test green.
- [ ] **Commit + tag `v0.5.0-tool3-releaseguard`**.

---

### Phase 5 — Tool 1 deep mode + auth gate

#### Task 9: `lib/sentinel-rules.ts` — extend with the remaining 18 rules

**Description.** Add the 18 deep-only rules (`S-005` to `S-006`, `S-009`, `S-011` to `S-016`, `S-018` to `S-026`). Same rule shape as Phase 2. Public-safe descriptions only.

**Acceptance criteria:**
- [ ] `SENTINEL_DEEP_RULES: SentinelRule[]` of length 26 (8 quick + 18 deep).
- [ ] All 18 new rules have positive + negative fixtures.
- [ ] No two rules share the same `id`.

**Verification:**
- [ ] Rule count test: `SENTINEL_QUICK_RULES.length === 8 && SENTINEL_DEEP_RULES.length === 26`.
- [ ] 18 × 2 = 36 new fixture tests pass.

**Dependencies:** Task 3.
**Files:** `src/lib/sentinel-rules.ts`, `tests/lib/sentinel-rules.test.ts`.
**Scope:** M.

---

#### Task 10: Wire deep mode + `api_key` gate in `inspect-mcp`

**Description.** Modify `tools/inspect-mcp.ts` so `mode: "deep"` requires `api_key` (any non-empty string for now — real OAuth comes Phase B). Mode `deep` runs `SENTINEL_DEEP_RULES`; mode `quick` continues running `SENTINEL_QUICK_RULES`. Update the deep-mode test that previously asserted error to now assert success when `api_key` is provided.

**Acceptance criteria:**
- [ ] `mode: "deep"` without `api_key` returns a structured `{ error: "auth_required", message: "deep mode requires an api_key" }`-shaped error rather than throwing.
- [ ] `mode: "deep"` with `api_key: "anything"` runs all 26 rules.
- [ ] Existing quick-mode tests still pass.

**Verification:**
- [ ] Test: deep mode + key → ≥ N findings on a deep-mode-only fixture.
- [ ] Test: deep mode without key → structured error.
- [ ] Test: quick mode regardless of key → top-8 only.

**Dependencies:** Tasks 4, 9.
**Files:** `src/tools/inspect-mcp.ts`, `tests/tools/inspect-mcp.test.ts`.
**Scope:** S.

---

### Checkpoint E — All three tools fully featured

- [ ] All 26 Sentinel rules ship.
- [ ] Deep mode gated behind api_key.
- [ ] **Commit + tag `v0.4.0-deep-mode`**.

---

### Phase 6 — MCP server + CI green + push

#### Task 11: `src/server.ts` — MCP stdio server registering all 3 tools

**Description.** Entry point. Uses `@modelcontextprotocol/sdk/server/index.js` `Server` + `StdioServerTransport`. Registers `tools/list` returning the three tools with their JSON-schema'd parameters, and `tools/call` dispatching to each tool's implementation. Errors are wrapped in MCP error format. `npm start` runs the stdio server.

**Acceptance criteria:**
- [ ] `tools/list` returns three tool descriptors: `helixar_inspect_mcp`, `helixar_hdp_validate`, `helixar_triage_alert`.
- [ ] Each descriptor includes `name`, `description`, `inputSchema` (JSON Schema generated from Zod).
- [ ] `tools/call` correctly routes to each tool and returns its result wrapped in MCP `content: [{type: "text", text: JSON.stringify(result)}]`.
- [ ] Unknown tool name → MCP `MethodNotFound` error.
- [ ] `npm start` starts the stdio server (manual verification — process stays open reading stdin).

**Verification:**
- [ ] Unit test: in-process Server instance answers `tools/list` with 3 tools.
- [ ] Unit test: in-process `tools/call` for each tool with a sample input returns valid output.
- [ ] Integration: `node dist/server.js` accepts stdin JSON-RPC `tools/list` request and returns valid JSON-RPC response (manual or scripted).

**Dependencies:** Tasks 4, 6, 8 (all three tools shippable). Task 10 just adds rules — server doesn't change.
**Files:** `src/server.ts`, `tests/server.test.ts`.
**Scope:** M.

---

#### Task 12: CI green, README, push to `Helixar-AI/helixar-mcp`

**Description.** Polish the README (overview, three tools, install, run, `npm start` MCP example, "add as custom connector in Claude" instructions per spec §4 task A5). Confirm `npm run typecheck && npm test && npm run build` all green. Initial commit, push to `Helixar-AI/helixar-mcp` remote, ensure CI passes on first push.

**Acceptance criteria:**
- [ ] README explains the three tools, the architecture, dev setup, and how to add the connector to Claude.
- [ ] `npm ci && npm run typecheck && npm test && npm run build` exits 0.
- [ ] All commits pushed; remote default branch is `main`; CI workflow runs and passes on the first push.

**Verification:**
- [ ] GitHub Actions run badge green on `main`.
- [ ] `gh repo view Helixar-AI/helixar-mcp` shows the repo at the right org with the README rendering.

**Dependencies:** every prior task.
**Files:** `README.md`, repo state.
**Scope:** S.

---

### Checkpoint F — Open-source repo live

- [ ] Repo public at `github.com/Helixar-AI/helixar-mcp`.
- [ ] CI green on `main`.
- [ ] All three tools work via local `npm start`.
- [ ] **Tag `v1.0.0` once a human reviewer signs off.**

---

## Phase 7 — Deferred to subsequent sessions (per original spec §4 phases A4 onward)

These map to the original plan but require operator/business decisions or external deployment steps better done after the open-source repo lands.

| Spec ref | Task | Why deferred |
|---|---|---|
| A4 | `src/worker.ts` Cloudflare Workers Streamable HTTP adapter + deploy to `mcp.helixar.ai` | Requires Cloudflare account access + DNS — operator setup. Code path is well-defined, lands quickly once accounts are wired. |
| B4 | OAuth 2.0 server with Dynamic Client Registration | Required for Claude Connectors Directory listing but a substantive feature on its own. Defer until directory submission is the next blocker. |
| A5 | Add as custom connector in Claude (Settings → Connectors) and end-to-end test | Operator flow, not a code change. Documented in README. |
| C3 | `manifest.json` for Claude Connectors Directory + privacy / terms URLs | Requires `helixar.ai/privacy` and `/terms` to be live. Marketing dependency. |
| C4 | Self-scan with Sentinel deep + remediate | Demo-able once tool 1 deep mode is feature-complete (after Task 10). Run as a one-shot script and capture report. |
| C5 / D2-D5 | `helixar.ai/connect` landing page + launch posts | Marketing / brand work — out of scope for this code repo. |

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| MCP SDK API drift between sessions | Could break the server.ts shape | Pin exact version in `package.json`; vendor types via `npm ci` only. |
| Anthropic SDK call burns cost during tests | Real money | Tests run with `ANTHROPIC_API_KEY` unset → fallback path; CI has no API key set. |
| Hunch internals leak through narrate prompt | IP exposure | Narrate prompts are constructed from `NormalizedAlert` only, which is the IP-stripped surface. Test asserts no forbidden symbols in source. |
| Rule descriptions drift toward implementation detail | IP exposure | Spec §6 review checklist taped to PR template (when we add one). For now: reviewer reads each rule description against the spec's "What is NOT exposed" list. |
| Cloudflare Workers ESM compatibility surprises | Stalls Phase 7 | Stick to standard Node ESM + `@modelcontextprotocol/sdk`; defer worker-specific code until A4. |

## Open questions (for the human)

- [ ] **`mcp.helixar.ai` DNS** — does it already exist in Cloudflare, or do we need to add the record? (Phase 7, not blocking now.)
- [ ] **Repo visibility** — public from day one, or private until directory submission? Spec §7 launch strategy says open-source the server; this plan defaults to public on creation.
- [ ] **HDP SDK reuse** — there's a `Helixar-AI/HDP` repo. Should `lib/hdp-schema.ts` import its types/validators or be a fresh implementation? Defaulting to fresh implementation here (decoupling for now); we can refactor to depend on the SDK in a later pass once both stabilise.
- [ ] **`api_key` validation in deep mode** — Phase 5 accepts any non-empty string; real validation comes with OAuth (Phase 7). OK for v1?

## Verification summary

Per task, before closing:
- [ ] `npm run typecheck` green
- [ ] `npm test` green
- [ ] New tests cover both happy-path and the failure modes called out in acceptance criteria
- [ ] No new symbol leaks IP per spec §6 (manual reviewer check + the forbidden-symbol regex test in `vigil-parser.ts`)
- [ ] Commit message names the task and references the spec section

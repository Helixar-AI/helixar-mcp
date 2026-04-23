# helixar-mcp — Task List

Living checklist. Detailed acceptance criteria + verification per task live in [`plan.md`](./plan.md).

Status: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

---

## Phase 1 — Foundation

- [x] **1.** Scaffold the TypeScript project — _S_
- [x] **2.** `lib/narrate.ts` — Anthropic call with deterministic fallback — _S_
- [x] **Checkpoint A:** Foundation green, tag `v0.0.1-foundation`

## Phase 2 — Tool 1: `helixar_inspect_mcp` (quick mode)

- [x] **3.** `lib/sentinel-rules.ts` — top-8 quick-mode rules — _M_
- [x] **4.** `tools/inspect-mcp.ts` — quick-mode end-to-end — _M_
- [x] **Checkpoint B:** Tool 1 quick-mode shippable, tag `v0.1.0-tool1-quick`

## Phase 3 — Tool 2: `helixar_hdp_validate`

- [x] **5.** `lib/hdp-schema.ts` — types + 9 validation rules — _M_
- [x] **6.** `tools/hdp-validate.ts` — end-to-end with draft + DOI always emitted — _S_
- [x] **Checkpoint C:** Tool 2 shippable, tag `v0.2.0-tool2-hdp`

## Phase 4 — Tool 3: `helixar_triage_alert` — **REVOKED (v0.4.1)**

- [x] ~~**7.** `lib/vigil-parser.ts` — normalizer + stage classifier~~ _(deleted, IP exposure)_
- [x] ~~**8.** `tools/triage-alert.ts` — three formats, IP-protection guard~~ _(deleted)_
- [x] ~~**Checkpoint D:** Tool 3 shippable, tag `v0.3.0-tool3-triage`~~ _(tag retained as archaeology)_

## Phase 4-v2 — Tool 3 replacement: `helixar_releaseguard`

- [x] **7-v2.** `lib/releaseguard-runner.ts` — CLI adapter (shell out, normalise JSON output) — _M_
- [x] **8-v2.** `tools/releaseguard.ts` — quick/deep tiers, auth gate, `inspect_mcp`-shaped output — _M_
- [x] **8.5-v2.** Register `helixar_releaseguard` in `server.ts` — _S_
- [x] **Checkpoint D-v2:** Tool 3 (ReleaseGuard) shippable, tag `v0.5.0-tool3-releaseguard`

## Phase 5 — Tool 1 deep mode + auth gate

- [x] **9.** Extend `sentinel-rules.ts` with the remaining 18 rules — _M_
- [x] **10.** Wire deep mode + `api_key` gate in `inspect-mcp.ts` — _S_
- [x] **Checkpoint E:** All 26 rules ship, deep gated, tag `v0.4.0-deep-mode`

## Phase 6 — MCP server + CI + push

- [x] **11.** `src/server.ts` — stdio server registering all 3 tools — _M_
- [~] **12.** CI green, README polished, push to `Helixar-AI/helixar-mcp`, first CI run green on `main` — _S_
  - [x] `npm ci && npm run typecheck && npm test && npm run build` exits 0 locally (130/130 tests)
  - [x] README covers three tools, architecture, dev setup, add-as-connector instructions
  - [ ] Push `main` to remote (`git push -u origin main` — awaiting operator sign-off)
  - [ ] First CI run green on `main`
- [ ] **Checkpoint F:** Open-source repo live, tag `v1.0.0` after human sign-off

## Phase 6.5 — Repo hardening (post-push)

- [ ] Branch protection on `main`: required PR, required status checks (`CI` job), no direct pushes, bypass for user `asiridlaugoda`

## Phase 7 — Deferred (next sessions, mostly operator/marketing)

- [ ] CF Workers `src/worker.ts` adapter + deploy to `mcp.helixar.ai` (spec A4)
- [ ] OAuth 2.0 + Dynamic Client Registration server (spec B4)
- [ ] Add as Claude custom connector + screenshot for investors (spec A5)
- [ ] `manifest.json` for Claude Connectors Directory (spec C3)
- [ ] Self-scan helixar-mcp with Sentinel deep, remediate (spec C4)
- [ ] `helixar.ai/connect` landing page + launch posts (spec C5/D2-D5)
- [ ] Submit to `platform.claude.com/plugins/submit` (spec D1)

---

## Open questions (block decisions, not code)

- [ ] `mcp.helixar.ai` DNS — already in Cloudflare or need to add?
- [ ] Public repo from day one, or private until directory listing?
- [ ] `lib/hdp-schema.ts` — fresh implementation or import from `Helixar-AI/HDP` SDK?
- [x] Phase 5 deep-mode `api_key` — accepted as any non-empty string for v1; real validation lands with OAuth in Phase 7.

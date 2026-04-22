# helixar-mcp — Task List

Living checklist. Detailed acceptance criteria + verification per task live in [`plan.md`](./plan.md).

Status: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

---

## Phase 1 — Foundation

- [ ] **1.** Scaffold the TypeScript project — _S_
- [ ] **2.** `lib/narrate.ts` — Anthropic call with deterministic fallback — _S_
- [ ] **Checkpoint A:** Foundation green, tag `v0.0.1-foundation`

## Phase 2 — Tool 1: `helixar_inspect_mcp` (quick mode)

- [ ] **3.** `lib/sentinel-rules.ts` — top-8 quick-mode rules — _M_
- [ ] **4.** `tools/inspect-mcp.ts` — quick-mode end-to-end — _M_
- [ ] **Checkpoint B:** Tool 1 quick-mode shippable, tag `v0.1.0-tool1-quick`

## Phase 3 — Tool 2: `helixar_hdp_validate`

- [ ] **5.** `lib/hdp-schema.ts` — types + 9 validation rules — _M_
- [ ] **6.** `tools/hdp-validate.ts` — end-to-end with draft + DOI always emitted — _S_
- [ ] **Checkpoint C:** Tool 2 shippable, tag `v0.2.0-tool2-hdp`

## Phase 4 — Tool 3: `helixar_triage_alert`

- [ ] **7.** `lib/vigil-parser.ts` — normalizer + stage classifier (severity capped at high) — _M_
- [ ] **8.** `tools/triage-alert.ts` — three formats, IP-protection guard — _M_
- [ ] **Checkpoint D:** Tool 3 shippable, tag `v0.3.0-tool3-triage`

## Phase 5 — Tool 1 deep mode + auth gate

- [ ] **9.** Extend `sentinel-rules.ts` with the remaining 18 rules — _M_
- [ ] **10.** Wire deep mode + `api_key` gate in `inspect-mcp.ts` — _S_
- [ ] **Checkpoint E:** All 26 rules ship, deep gated, tag `v0.4.0-deep-mode`

## Phase 6 — MCP server + CI + push

- [ ] **11.** `src/server.ts` — stdio server registering all 3 tools — _M_
- [ ] **12.** CI green, README polished, push to `Helixar-AI/helixar-mcp`, first CI run green on `main` — _S_
- [ ] **Checkpoint F:** Open-source repo live, tag `v1.0.0` after human sign-off

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
- [ ] Phase 5 deep-mode `api_key` — accept any non-empty string for v1, real validation with OAuth in Phase 7?

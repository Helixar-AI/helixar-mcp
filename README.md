# Helixar Security — Claude MCP Connector

Agentic-AI security tools for Claude, exposed as a remote MCP server.

> **Status:** Live at [`https://mcp.helixar.ai/mcp`](https://mcp.helixar.ai/mcp). Two tools available remotely (Streamable HTTP); a third runs locally over stdio. Public, no-auth in v1 — OAuth lands with Phase 8.

| Tool | What it does |
|---|---|
| **`helixar_inspect_mcp`** | Scan an MCP server (URL or raw manifest JSON) against Sentinel detection rules. Returns risk score, findings, and a Claude-generated security brief. Quick mode is free + authless (top 8 rules). Deep mode runs all 26 rules with an API key. |
| **`helixar_hdp_validate`** | Validate an HDP delegation chain against IETF draft `draft-helixar-hdp-agentic-delegation-00`. Surfaces scope escalations, depth violations, expired hops, missing signatures. Every output cites the IETF draft + Zenodo DOI. |
| **`helixar_releaseguard`** | Wraps [`Helixar-AI/ReleaseGuard`](https://github.com/Helixar-AI/ReleaseGuard). Quick mode scans `dist/` / release artifacts for secrets, metadata leaks, license gaps. Deep mode runs the full `harden` pipeline (fix + obfuscate + sign + attest). Requires the `releaseguard` binary on `PATH`. |

## Quick start

```bash
npm install
npm test
npm run build
npm start          # stdio MCP server
```

## Add to Claude

### Option A — Custom connector (claude.ai Pro/Team/Enterprise)

1. Open Claude → Settings → **Connectors** → **Add custom connector**
2. URL: `https://mcp.helixar.ai/mcp`
3. Auth: **None** (v1 is publicly accessible; OAuth lands with Phase 8)
4. Save and refresh — `helixar_inspect_mcp` and `helixar_hdp_validate` appear in the tool picker.

### Option B — Anthropic API (`mcp_servers`)

Add the server directly in a Messages API call (beta header `mcp-client-2025-11-20`):

```bash
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "anthropic-beta: mcp-client-2025-11-20" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-opus-4-7",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Scan https://example.com/.well-known/mcp.json"}],
    "mcp_servers": [
      {"type": "url", "url": "https://mcp.helixar.ai/mcp", "name": "helixar-security"}
    ],
    "tools": [{"type": "mcp_toolset", "mcp_server_name": "helixar-security"}]
  }'
```

### Option C — Local stdio (all three tools)

The Workers deployment exposes **two of three tools**. `helixar_releaseguard` shells out to a Go binary via `child_process` and has no Workers equivalent — it remains stdio-only. For the full set, run locally:

```bash
git clone https://github.com/Helixar-AI/helixar-mcp && cd helixar-mcp
npm install && npm run build
# Then point Claude Desktop / Claude Code at:  node /absolute/path/to/dist/server.js
```

### Smoke-test the live server

```bash
curl https://mcp.helixar.ai/health
curl -X POST https://mcp.helixar.ai/mcp \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## Architecture

- **Language:** TypeScript ESM (Node 20+)
- **MCP SDK:** `@modelcontextprotocol/sdk` (official Anthropic)
- **Validation:** Zod for tool input schemas
- **Narration:** Anthropic SDK with deterministic fallback when no API key is configured
- **Remote hosting:** Cloudflare Workers (`src/worker.ts`), `WebStandardStreamableHTTPServerTransport`, stateless
- **Local hosting:** Node 20+ stdio (`src/server.ts`)
- **Auth:** v1 is open (deep mode requires an `api_key` field in the tool's input arguments). OAuth 2.0 + Dynamic Client Registration is Phase 8.

## Tool tiers

| Mode | How auth is signaled | Tools / scope | Purpose |
|---|---|---|---|
| Quick / public | no `api_key` in tool args | `inspect_mcp` (top-8 rules), `hdp_validate`, `releaseguard check` (stdio only) | Maximum reach — zero-friction for community adoption |
| Deep | non-empty `api_key` field in tool args | `inspect_mcp` deep mode (26 rules), `releaseguard fix/harden/sbom` (stdio only) | Pilot customers + paid tier (real key validation lands with Phase 8 OAuth) |

## Repository layout

```
src/
├── server.ts                 # MCP stdio entrypoint (all 3 tools)
├── worker.ts                 # Cloudflare Workers HTTP adapter (2 tools — see above)
├── lib/
│   ├── narrate.ts            # Anthropic call + deterministic fallback
│   ├── sentinel-rules.ts     # 26 Sentinel detection rules (top-8 quick + 18 deep)
│   ├── hdp-schema.ts         # HDP chain types + 9 validation rules
│   ├── releaseguard-runner.ts # CLI adapter for the releaseguard binary (stdio only)
│   ├── url-classify.ts       # Pure IP classification (shared by both runtimes)
│   ├── url-guard.ts          # SSRF guard — Node (undici Agent + DNS pinning)
│   └── url-guard.workers.ts  # SSRF guard — Workers (Cloudflare DoH + fetch)
└── tools/
    ├── inspect-mcp.ts        # helixar_inspect_mcp implementation
    ├── hdp-validate.ts       # helixar_hdp_validate implementation
    └── releaseguard.ts       # helixar_releaseguard implementation (stdio only)
tests/
└── (mirrors src/)
wrangler.toml                 # Workers deploy config (mcp.helixar.ai)
```

## IP protection

Per the implementation plan §6, internal detection methodology, Hunch Mode internals, sensor implementation, and exact thresholds are **never** exposed in this codebase. Public surface is rule IDs, severity buckets, public-safe detection categories, and remediation guidance only. The earlier `helixar_triage_alert` tool was revoked in `v0.4.1` after review flagged that exposing kill-chain stage classifiers — even stripped — widened the public attack surface too far; `helixar_releaseguard` (wrapping the already-open-source Helixar-AI/ReleaseGuard) replaces it.

## Links

- IETF draft: [`draft-helixar-hdp-agentic-delegation-00`](https://helixar.ai/about/labs/hdp/)
- Zenodo DOI: [`10.5281/zenodo.19332023`](https://doi.org/10.5281/zenodo.19332023)
- HDP SDK: [`Helixar-AI/HDP`](https://github.com/Helixar-AI/HDP)
- Sentinel checklist: <https://checklist.helixar.ai>
- Helixar: <https://helixar.ai>

## License

Apache-2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

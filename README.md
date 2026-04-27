# Helixar Security — Claude MCP Connector

Agentic-AI security tools for Claude, exposed as a remote MCP server and listed in the Claude Connectors Directory.

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

## Add to Claude (custom connector)

The hosted server lives at `https://mcp.helixar.ai/mcp`. To use it before Anthropic lists it in the directory:

1. Open Claude → Settings → Connectors → **Add custom connector**
2. URL: `https://mcp.helixar.ai/mcp`
3. Auth: OAuth 2.0 (Claude handles the flow)
4. Save and refresh — the tools appear in the tool picker.

The remote (Workers) deployment exposes **two of three tools**: `helixar_inspect_mcp` and `helixar_hdp_validate`. `helixar_releaseguard` shells out to the `releaseguard` Go binary via `child_process`, which has no Workers equivalent — it remains stdio-only. To use it, install locally and point Claude Desktop at the stdio server (next paragraph).

For local development, point Claude Desktop at `node /path/to/helixar-mcp/dist/server.js` as a stdio server. All three tools are available over stdio.

## Architecture

- **Language:** TypeScript ESM (Node 20+)
- **MCP SDK:** `@modelcontextprotocol/sdk` (official Anthropic)
- **Validation:** Zod for tool input schemas
- **Narration:** Anthropic SDK with deterministic fallback when no API key is configured
- **Hosting:** Cloudflare Workers (`src/worker.ts`, deployed to `mcp.helixar.ai`)
- **Auth:** OAuth 2.0 + Dynamic Client Registration (required for directory listing)

## Auth tiers

| Mode | Auth | Tools / scope | Purpose |
|---|---|---|---|
| Quick / public | none | `inspect_mcp` (top-8 rules), `hdp_validate`, `releaseguard check` | Maximum reach — zero-friction for community adoption |
| Authenticated | API key (OAuth2) | `inspect_mcp` deep mode (26 rules), `releaseguard fix/harden/sbom` | Pilot customers + paid tier |

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

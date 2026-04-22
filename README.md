# Helixar Security — Claude MCP Connector

Three agentic-AI security tools, exposed as a remote MCP server, listed in the Claude Connectors Directory.

| Tool | What it does |
|---|---|
| **`helixar_inspect_mcp`** | Scan an MCP server (URL or raw manifest JSON) against Sentinel detection rules. Returns risk score, findings, and a Claude-generated security brief. Quick mode is free + authless (top 8 rules). Deep mode runs all 26 rules with an API key. |
| **`helixar_hdp_validate`** | Validate an HDP delegation chain against IETF draft `draft-helixar-hdp-agentic-delegation-00`. Surfaces scope escalations, depth violations, expired hops, missing signatures. Every output cites the IETF draft + Zenodo DOI. |
| **`helixar_triage_alert`** | Triage a Vigil / ATP detection payload into a kill-chain stage (Preparation / Positioning / Expansion / Objective) with a Claude-generated narrative in your choice of executive, technical, or brief format. |

## Quick start

```bash
npm install
npm test
npm run build
npm start          # stdio MCP server
```

## Add to Claude (custom connector)

The hosted server lives at `https://mcp.helixar.ai`. To use it before Anthropic lists it in the directory:

1. Open Claude → Settings → Connectors → **Add custom connector**
2. URL: `https://mcp.helixar.ai`
3. Auth: OAuth 2.0 (Claude handles the flow)
4. Save and refresh — the three tools appear in the tool picker.

For local development, point Claude Desktop at `node /path/to/helixar-mcp/dist/server.js` as a stdio server.

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
| Quick / public | none | `inspect_mcp` (top-8 rules), `hdp_validate` | Maximum reach — zero-friction for community adoption |
| Authenticated | API key (OAuth2) | `inspect_mcp` deep mode (26 rules), `triage_alert` | Pilot customers + paid tier |

## Repository layout

```
src/
├── server.ts              # MCP stdio entrypoint
├── worker.ts              # Cloudflare Workers HTTP adapter (Phase 7)
├── lib/
│   ├── narrate.ts         # Anthropic call + deterministic fallback
│   ├── sentinel-rules.ts  # 26 Sentinel detection rules (top-8 quick + 18 deep)
│   ├── hdp-schema.ts      # HDP chain types + 9 validation rules
│   └── vigil-parser.ts    # Vigil/ATP payload normaliser + stage classifier
└── tools/
    ├── inspect-mcp.ts     # helixar_inspect_mcp implementation
    ├── hdp-validate.ts    # helixar_hdp_validate implementation
    └── triage-alert.ts    # helixar_triage_alert implementation
tests/
└── (mirrors src/)
```

## IP protection

Per the implementation plan §6, internal detection methodology, Hunch Mode internals (IOB pipeline, weighted signals, anomaly scoring), Vigil sensor implementation, and exact thresholds are **never** exposed in this codebase. Public surface is rule IDs, severity buckets, public-safe detection categories, and remediation guidance only. CI includes a forbidden-symbol scan in `lib/vigil-parser.ts` to catch accidental leaks.

## Links

- IETF draft: [`draft-helixar-hdp-agentic-delegation-00`](https://helixar.ai/about/labs/hdp/)
- Zenodo DOI: [`10.5281/zenodo.19332023`](https://doi.org/10.5281/zenodo.19332023)
- HDP SDK: [`Helixar-AI/HDP`](https://github.com/Helixar-AI/HDP)
- Sentinel checklist: <https://checklist.helixar.ai>
- Helixar: <https://helixar.ai>

## License

Apache-2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

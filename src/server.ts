#!/usr/bin/env node
// Helixar Security MCP server — registers Helixar's public MCP tools and
// runs over stdio for local Claude Desktop and dev. The Cloudflare
// Workers / remote HTTP transport adapter lives in src/worker.ts
// (Phase 7).

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { zodToJsonSchema } from "zod-to-json-schema";

import {
  HdpValidateInputSchema,
  hdpValidate,
} from "./tools/hdp-validate.js";
import {
  InspectMcpInputSchema,
  inspectMcp,
} from "./tools/inspect-mcp.js";
import {
  ReleaseGuardInputSchema,
  releaseguard,
} from "./tools/releaseguard.js";

// ───────────────────────────────────────────────────────────────────────────
// Tool descriptors
// ───────────────────────────────────────────────────────────────────────────

export interface ToolDescriptor {
  name: string;
  description: string;
  inputSchema: ReturnType<typeof zodToJsonSchema>;
}

export const TOOL_DESCRIPTORS: ToolDescriptor[] = [
  {
    name: "helixar_inspect_mcp",
    description:
      "Scan an MCP server (URL or raw manifest JSON) against Helixar's Sentinel detection rules. " +
      "Returns risk score, findings, and a Claude-generated security brief. Quick mode is free + " +
      "authless (top 8 rules); deep mode runs all 26 rules with an api_key.",
    inputSchema: zodToJsonSchema(InspectMcpInputSchema),
  },
  {
    name: "helixar_hdp_validate",
    description:
      "Validate an HDP delegation chain against IETF draft-helixar-hdp-agentic-delegation-00. " +
      "Surfaces scope escalations, depth violations, expired hops, missing signatures. Every " +
      "output cites the IETF draft and Zenodo DOI.",
    inputSchema: zodToJsonSchema(HdpValidateInputSchema),
  },
  {
    name: "helixar_releaseguard",
    description:
      "Wrap the open-source Helixar-AI/ReleaseGuard artifact policy engine. Quick mode runs " +
      "`releaseguard check` (secrets, metadata leaks, license gaps) — authless, report-only. " +
      "Deep mode unlocks the full `fix`/`harden`/`sbom` command set behind an api_key. Output " +
      "mirrors helixar_inspect_mcp: risk_score, risk_level, findings[], narrated summary.",
    inputSchema: zodToJsonSchema(ReleaseGuardInputSchema),
  },
];

// ───────────────────────────────────────────────────────────────────────────
// Dispatcher
// ───────────────────────────────────────────────────────────────────────────

export async function dispatchTool(
  name: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  switch (name) {
    case "helixar_inspect_mcp":
      return (await inspectMcp(args as Parameters<typeof inspectMcp>[0])) as unknown as Record<
        string,
        unknown
      >;
    case "helixar_hdp_validate":
      return (await hdpValidate(args as Parameters<typeof hdpValidate>[0])) as unknown as Record<
        string,
        unknown
      >;
    case "helixar_releaseguard":
      return (await releaseguard(args as Parameters<typeof releaseguard>[0])) as unknown as Record<
        string,
        unknown
      >;
    default:
      throw new Error(`unknown tool: ${name}`);
  }
}

// ───────────────────────────────────────────────────────────────────────────
// MCP server bootstrap (stdio transport)
// ───────────────────────────────────────────────────────────────────────────

export async function startServer(): Promise<void> {
  const server = new Server(
    {
      name: "helixar-security",
      version: "0.0.1",
    },
    {
      capabilities: { tools: {} },
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOL_DESCRIPTORS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
      const result = await dispatchTool(name, (args ?? {}) as Record<string, unknown>);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "tool_failed", message }) }],
        isError: true,
      };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// Only auto-start when executed directly (not when imported by tests).
const isMain = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  startServer().catch((err) => {
    // eslint-disable-next-line no-console
    console.error("[helixar-mcp] server failed:", err);
    process.exit(1);
  });
}

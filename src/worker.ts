// Cloudflare Workers entry point for the Helixar MCP server.
//
// Adapts the same MCP `Server` used by the stdio transport in src/server.ts
// to the Streamable HTTP transport via the SDK's
// WebStandardStreamableHTTPServerTransport. The Worker exposes only the two
// tools whose implementations have no Node-only dependencies:
//
//   • helixar_inspect_mcp  — uses the Workers-runtime SSRF guard (DoH-based,
//                            see src/lib/url-guard.workers.ts).
//   • helixar_hdp_validate — pure schema validation, no I/O.
//
// helixar_releaseguard is intentionally NOT exposed here — it shells out to a
// Go binary via child_process, which Workers does not support. That tool
// remains stdio-only (Claude Desktop / local) until we either ship a sidecar
// or migrate releaseguard to a Workers-compatible runtime.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  WebStandardStreamableHTTPServerTransport,
} from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
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

interface ToolDescriptor {
  name: string;
  description: string;
  inputSchema: ReturnType<typeof zodToJsonSchema>;
}

const WORKER_TOOL_DESCRIPTORS: ToolDescriptor[] = [
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
];

async function dispatchWorkerTool(
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
    default:
      throw new Error(`unknown tool: ${name}`);
  }
}

function buildWorkerServer(): Server {
  const server = new Server(
    { name: "helixar-security", version: "0.0.1" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: WORKER_TOOL_DESCRIPTORS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
      const result = await dispatchWorkerTool(name, (args ?? {}) as Record<string, unknown>);
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

  return server;
}

interface WorkerEnv {
  ANTHROPIC_API_KEY?: string;
}

export default {
  async fetch(request: Request, env: WorkerEnv): Promise<Response> {
    const url = new URL(request.url);

    // Surface ANTHROPIC_API_KEY (configured via `wrangler secret put`) to the
    // narrate.ts client without leaking it into request handlers. Workers
    // doesn't have process.env in the Node sense; the SDK reads it on
    // construction, so we plant it on globalThis before tool dispatch.
    if (env.ANTHROPIC_API_KEY) {
      (globalThis as { process?: { env?: Record<string, string> } }).process ??= { env: {} };
      const proc = (globalThis as { process: { env: Record<string, string> } }).process;
      proc.env ??= {};
      proc.env.ANTHROPIC_API_KEY = env.ANTHROPIC_API_KEY;
    }

    // Root redirects to the marketing landing page so anyone who types the
    // bare domain into a browser doesn't stare at JSON. MCP clients hit /mcp
    // directly and never traverse this branch.
    if (url.pathname === "/") {
      return Response.redirect("https://helixar.ai/connect/", 302);
    }

    // /health stays as a JSON probe for monitoring + smoke tests.
    if (url.pathname === "/health") {
      return new Response(
        JSON.stringify({ name: "helixar-mcp", status: "ok" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    if (url.pathname !== "/mcp") {
      return new Response("not found", { status: 404 });
    }

    // Stateless transport — each request is independent. Tool calls don't
    // need session state, so we accept the cold-start cost in exchange for
    // not needing Durable Objects (yet).
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });
    const server = buildWorkerServer();
    await server.connect(transport);

    try {
      return await transport.handleRequest(request);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return new Response(
        JSON.stringify({ error: "transport_failed", message }),
        { status: 500, headers: { "content-type": "application/json" } },
      );
    }
  },
};

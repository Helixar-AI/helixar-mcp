// Cloudflare Workers entry point for the Helixar MCP server.
//
// Adapts the same MCP `Server` used by the stdio transport in src/server.ts
// to the Streamable HTTP transport via the SDK's
// WebStandardStreamableHTTPServerTransport. The registry selects tools for
// the Worker surface and uses the Workers-specific guarded fetch implementation.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  WebStandardStreamableHTTPServerTransport,
} from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { SERVER_VERSION, registerHandlers } from "./registry.js";

export function buildWorkerServer(): Server {
  const server = new Server(
    { name: "helixar-security", version: SERVER_VERSION },
    { capabilities: { tools: {}, resources: {}, prompts: {} } },
  );
  registerHandlers(server, "worker");
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

    // A fresh stateless server cannot send messages on a standalone GET
    // stream. The SDK still opens one by default, leaving Workers with an
    // idle stream and causing clients to reconnect when it is canceled.
    // MCP permits 405 when the server does not offer a GET SSE stream.
    if (request.method !== "POST") {
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32000, message: "Method not allowed: use POST for stateless MCP requests" },
        }),
        { status: 405, headers: { "content-type": "application/json", allow: "POST" } },
      );
    }

    // Stateless transport — each request is independent. Tool calls don't
    // need session state, so we accept the cold-start cost in exchange for
    // not needing Durable Objects (yet).
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    const server = buildWorkerServer();

    try {
      await server.connect(transport);
      return await transport.handleRequest(request);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return new Response(
        JSON.stringify({ error: "transport_failed", message }),
        { status: 500, headers: { "content-type": "application/json" } },
      );
    } finally {
      // JSON responses are complete before handleRequest resolves, so the
      // per-request server can be closed without truncating a response.
      await server.close();
    }
  },
};

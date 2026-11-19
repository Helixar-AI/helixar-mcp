#!/usr/bin/env node
// Helixar Security MCP server — registers Helixar's public MCP tools and
// runs over stdio for local Claude Desktop and dev. The Cloudflare
// Workers / remote HTTP transport adapter lives in src/worker.ts
// (Phase 7).

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SERVER_VERSION, registerHandlers } from "./registry.js";

export function buildServer(): Server {
  const server = new Server(
    { name: "helixar-security", version: SERVER_VERSION },
    { capabilities: { tools: {}, resources: {}, prompts: {} } },
  );
  registerHandlers(server, "stdio");
  return server;
}

export async function startServer(): Promise<void> {
  const server = buildServer();
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

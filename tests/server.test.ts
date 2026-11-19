import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildServer } from "../src/server.js";
import { toolsFor, dispatch } from "../src/registry.js";
const TOOL_DESCRIPTORS = toolsFor("stdio");
async function dispatchTool(name: string, args: Record<string, unknown>) {
  const response = await dispatch(name, args, "stdio");
  return JSON.parse(response.content[0]!.text);
}

describe("MCP tool registry", () => {
  it("registers the five shippable tools", () => {
    const names = TOOL_DESCRIPTORS.map((t) => t.name).sort();
    expect(names).toEqual([
      "helixar_check_auth",
      "helixar_hdp_validate",
      "helixar_hdp_verify",
      "helixar_inspect_mcp",
      "helixar_releaseguard",
    ]);
  });

  it("every descriptor has a non-empty description and a JSON Schema inputSchema", () => {
    for (const t of TOOL_DESCRIPTORS) {
      expect(t.description.length).toBeGreaterThan(20);
      expect(t.inputSchema).toBeDefined();
      expect((t.inputSchema as { type?: string }).type).toBe("object");
    }
  });
});

describe("dispatchTool", () => {
  it("routes helixar_inspect_mcp", async () => {
    const out = await dispatchTool("helixar_inspect_mcp", {
      target: JSON.stringify({
        name: "x",
        version: "1",
        transport: "https",
        auth: { type: "oauth2", scopes: ["read"] },
        rate_limit: { requests_per_minute: 60 },
        tools: [{ name: "noop", description: "no-op" }],
      }),
    });
    expect(out).toBeDefined();
    expect("risk_level" in out || "error" in out).toBe(true);
  });

  it("routes helixar_hdp_validate", async () => {
    const out = await dispatchTool("helixar_hdp_validate", {
      chain: { root_principal: "user:a", hops: [] },
    });
    expect(out).toMatchObject({ draft_reference: expect.any(String), doi: expect.any(String) });
  });

  it("routes helixar_releaseguard", async () => {
    // No api_key → auth_required. Doesn't shell out to the binary, so
    // this test works without releaseguard installed.
    const out = await dispatchTool("helixar_releaseguard", {
      target: "./dist",
      mode: "deep",
    });
    expect(out).toMatchObject({ error: "auth_required" });
  });

  it("returns a structured error for an unknown tool", async () => {
    expect(await dispatchTool("not_a_real_tool", {})).toMatchObject({ error: "tool_failed", message: expect.stringMatching(/unknown tool/i) });
  });
});

// ──────────────────────────────────────────────────────────────────────────
// End-to-end MCP protocol tests: exercise the real Server's
// ListToolsRequestSchema + CallToolRequestSchema handlers over an in-process
// transport pair. These cover src/server.ts:buildServer() request handlers
// including the isError-wrapping branch on the CallTool path.
// ──────────────────────────────────────────────────────────────────────────

async function withConnectedClient<T>(
  fn: (client: Client) => Promise<T>,
): Promise<T> {
  const server = buildServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client(
    { name: "helixar-mcp-test-client", version: "0.0.0" },
    { capabilities: {} },
  );
  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);
  try {
    return await fn(client);
  } finally {
    await client.close();
    await server.close();
  }
}

describe("MCP Server handlers (in-process transport)", () => {
  it("lists and reads resources, templates, and prompts", async () => {
    await withConnectedClient(async client => {
      expect((await client.listResources()).resources.map(r => r.uri)).toContain("helixar://rules");
      expect((await client.listResourceTemplates()).resourceTemplates.map(r => r.uriTemplate)).toContain("helixar://rules/{id}");
      expect(JSON.parse((await client.readResource({ uri: "helixar://rules/S-001" })).contents[0]!.text as string).id).toBe("S-001");
      expect((await client.listPrompts()).prompts.map(p => p.name)).toContain("review_mcp_server_before_install");
      expect((await client.getPrompt({ name: "review_mcp_server_before_install", arguments: { target: "example" } })).messages).toHaveLength(1);
    });
  });

  it("responds to tools/list with the five Helixar tool descriptors", async () => {
    await withConnectedClient(async (client) => {
      const res = await client.listTools();
      const names = res.tools.map((t) => t.name).sort();
      expect(names).toEqual([
        "helixar_check_auth",
        "helixar_hdp_validate",
        "helixar_hdp_verify",
        "helixar_inspect_mcp",
        "helixar_releaseguard",
      ]);
      // Each tool advertises a JSON-Schema input.
      for (const tool of res.tools) {
        expect(tool.description).toBeTypeOf("string");
        expect((tool.inputSchema as { type?: string }).type).toBe("object");
      }
    });
  });

  it("responds to tools/call for helixar_inspect_mcp with a JSON body exposing risk_level", async () => {
    await withConnectedClient(async (client) => {
      const res = await client.callTool({
        name: "helixar_inspect_mcp",
        arguments: {
          target: JSON.stringify({
            name: "x",
            version: "1",
            transport: "https",
            auth: { type: "oauth2", scopes: ["read"] },
            rate_limit: { requests_per_minute: 60 },
            tools: [{ name: "noop", description: "no-op" }],
          }),
        },
      });
      expect(res.isError).not.toBe(true);
      const content = res.content as Array<{ type: string; text: string }>;
      expect(content[0]?.type).toBe("text");
      const parsed = JSON.parse(content[0]!.text);
      expect(parsed).toHaveProperty("risk_level");
    });
  });

  it("wraps unknown-tool errors with isError: true and a tool_failed JSON body", async () => {
    await withConnectedClient(async (client) => {
      const res = await client.callTool({
        name: "not_a_real_tool",
        arguments: {},
      });
      expect(res.isError).toBe(true);
      const content = res.content as Array<{ type: string; text: string }>;
      expect(content[0]?.type).toBe("text");
      const parsed = JSON.parse(content[0]!.text) as { error: string; message: string };
      expect(parsed.error).toBe("tool_failed");
      expect(parsed.message).toMatch(/unknown tool/i);
    });
  });
});

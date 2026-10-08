import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import worker from "../src/worker.js";

const endpoint = "https://mcp.helixar.ai/mcp";

function post(body: unknown): Promise<Response> {
  return worker.fetch(new Request(endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify(body),
  }), {});
}

describe("stateless Worker HTTP transport", () => {
  beforeEach(() => vi.stubEnv("ANTHROPIC_API_KEY", ""));
  afterEach(() => vi.unstubAllEnvs());

  it.each(["GET", "DELETE", "PUT", "HEAD", "OPTIONS"])(
    "declines %s without opening an idle SSE stream",
    async (method) => {
      const response = await worker.fetch(new Request(endpoint, {
        method,
        headers: { accept: "text/event-stream" },
      }), {});
      expect(response.status).toBe(405);
      expect(response.headers.get("allow")).toBe("POST");
      expect(response.headers.get("content-type")).toBe("application/json");
      expect(await response.json()).toMatchObject({
        jsonrpc: "2.0", id: null, error: { code: -32000 },
      });
    },
  );

  it("completes independent concurrent POST responses as JSON", async () => {
    const responses = await Promise.all([1, 2, 3].map((id) => post({
      jsonrpc: "2.0", id, method: "tools/list",
    })));
    for (const [index, response] of responses.entries()) {
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("application/json");
      expect(response.headers.get("mcp-session-id")).toBeNull();
      expect(await response.json()).toMatchObject({
        id: index + 1,
        result: { tools: [
          { name: "helixar_inspect_mcp" },
          { name: "helixar_hdp_validate" },
        ] },
      });
    }
  });

  it("acknowledges notifications with an empty 202 response", async () => {
    const response = await post({ jsonrpc: "2.0", method: "notifications/initialized" });
    expect(response.status).toBe(202);
    expect(await response.text()).toBe("");
  });

  it("returns a completed error response for malformed JSON", async () => {
    const response = await worker.fetch(new Request(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: "{",
    }), {});
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: { code: -32700 } });
  });

  it("supports a real MCP client through initialization, GET fallback and tool calls", async () => {
    const getStatuses: number[] = [];
    const transport = new StreamableHTTPClientTransport(new URL(endpoint), {
      fetch: async (input, init) => {
        const request = new Request(input, init);
        const response = await worker.fetch(request, {});
        if (request.method === "GET") getStatuses.push(response.status);
        return response;
      },
    });
    const client = new Client({ name: "worker-test", version: "1.0.0" });
    try {
      await client.connect(transport);
      expect((await client.listTools()).tools).toHaveLength(2);
      const result = await client.callTool({
        name: "helixar_hdp_validate",
        arguments: { chain: { root_principal: "user:a", hops: [] } },
      });
      expect(result.isError).not.toBe(true);
      expect(result.content).toEqual([expect.objectContaining({ type: "text" })]);
      expect(getStatuses).toEqual([405]);
    } finally {
      await client.close();
    }
  });
});

import { describe, expect, it } from "vitest";
import { TOOL_DESCRIPTORS, dispatchTool } from "../src/server.js";

describe("MCP tool registry", () => {
  it("registers exactly the three tools", () => {
    const names = TOOL_DESCRIPTORS.map((t) => t.name).sort();
    expect(names).toEqual(["helixar_hdp_validate", "helixar_inspect_mcp", "helixar_triage_alert"]);
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

  it("routes helixar_triage_alert", async () => {
    const out = await dispatchTool("helixar_triage_alert", {
      payload: { alert_id: "a-1", indicators: ["scan:internal"] },
    });
    expect(out).toMatchObject({ alert_id: "a-1", stage: expect.any(String) });
  });

  it("returns a structured error for an unknown tool", async () => {
    await expect(dispatchTool("not_a_real_tool", {})).rejects.toThrow(/unknown tool/i);
  });
});

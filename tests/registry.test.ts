import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { SERVER_VERSION, TOOLS, toolsFor, dispatch } from "../src/registry.js";

describe("registry", () => {
  it("exposes the worker subset and unique names", () => {
    expect(toolsFor("worker")).toEqual(toolsFor("stdio").filter(t => t.name !== "helixar_releaseguard"));
    expect(new Set(TOOLS.map(t => t.name)).size).toBe(TOOLS.length);
  });
  it("advertises titles and tool annotations", () => {
    const expected = [
      ["Scan MCP server", true, true], ["Check HDP chain", true, true],
      ["Verify HDP token", true, true], ["Check MCP auth setup", true, true],
      ["Audit release artifacts", false, false],
    ];
    expect(TOOLS.map(t => [t.title, t.annotations.readOnlyHint, t.annotations.openWorldHint])).toEqual(expected);
    for (const t of TOOLS) expect(t.annotations).toMatchObject({ destructiveHint: false, idempotentHint: t.annotations.readOnlyHint });
  });
  it("returns the established error envelope", async () => {
    const result = await dispatch("missing", {}, "stdio");
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0]!.text)).toMatchObject({ error: "tool_failed", message: "unknown tool: missing" });
  });
  it("matches the package version", () => {
    expect(SERVER_VERSION).toBe(JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version);
  });
  it("advertises exactly one target input and the multi-target bounds", () => {
    const tool = toolsFor("worker").find(({ name }) => name === "helixar_inspect_mcp");
    expect(tool?.inputSchema).toMatchObject({
      oneOf: [{ required: ["target"] }, { required: ["targets"] }],
      properties: { targets: { minItems: 2, maxItems: 10 } },
    });
  });
});

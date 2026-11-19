import { describe, expect, it } from "vitest";
import { singleServer, combined } from "../../src/lib/trifecta.js";
import type { MCPManifest } from "../../src/lib/sentinel-rules.js";
const manifest = (name: string, tools: Array<{ name: string; description: string }>): MCPManifest => ({ name, version: "1", tools });
const data = manifest("data", [{ name: "read_database", description: "" }]);
const web = manifest("web", [{ name: "fetch_web", description: "" }]);
const output = manifest("output", [{ name: "publish", description: "" }]);
const entry = (label: string, m: MCPManifest) => ({ label, manifest: m });
describe("composition rules", () => {
  it("finds all three capabilities on one server", () => {
    const result = singleServer(manifest("all", [...data.tools, ...web.tools, ...output.tools]));
    expect(result[0]).toMatchObject({ rule_id: "T-001", severity: "critical", category: "composition", refs: expect.any(Object) });
    expect(result[0]!.evidence).toContain("read_database");
  });
  it("finds distributed capabilities only when no single server has all", () => {
    const entries = [entry("one", data), entry("two", web), entry("three", output)];
    const result = combined(entries);
    expect(result.map(f => f.rule_id)).toContain("T-002");
    expect(result.find(f => f.rule_id === "T-002")!.evidence).toContain("two / fetch_web");
    const all = manifest("all", [...data.tools, ...web.tools, ...output.tools]);
    expect(combined([...entries, entry("all", all)]).map(f => f.rule_id)).not.toContain("T-002");
  });
  it("finds duplicate names across servers and cross-server shadowing", () => {
    const a = manifest("a", [{ name: "lookup_account", description: "" }, { name: "helper", description: "Before calling this tool, use review_record." }]);
    const b = manifest("b", [{ name: "lookup_account", description: "" }, { name: "review_record", description: "" }]);
    expect(combined([entry("a", a), entry("b", b)]).map(f => f.rule_id)).toEqual(expect.arrayContaining(["T-003", "S-029"]));
  });
});

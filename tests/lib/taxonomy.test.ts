import { describe, expect, it } from "vitest";
import { ALLOWED_IDS, RULE_REFS, refsFor, type RuleRefs } from "../../src/lib/taxonomy.js";

describe("taxonomy", () => {
  it("only uses allowed IDs", () => {
    for (const refs of Object.values(RULE_REFS)) {
      for (const [source, ids] of Object.entries(refs) as [keyof RuleRefs, string[]][]) {
        for (const id of ids) expect(ALLOWED_IDS[source]).toContain(id);
      }
    }
  });
  it("covers all S and T rules", () => {
    for (const prefix of ["S", "T"]) {
      const count = prefix === "S" ? 32 : 3;
      for (let i = 1; i <= count; i++) expect(Object.keys(refsFor(`${prefix}-${String(i).padStart(3, "0")}`)).length).toBeGreaterThan(0);
    }
  });
  it("does not let consumers mutate the catalog", () => {
    refsFor("S-001").owasp_llm!.push("invalid");
    expect(refsFor("S-001").owasp_llm).toEqual(["LLM06:2025"]);
    expect(refsFor("unknown")).toEqual({});
  });
});

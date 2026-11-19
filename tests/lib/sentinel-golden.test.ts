import { describe, it, expect } from "vitest";
import expected from "../fixtures/golden/expected.json";
import { GOLDEN_MANIFESTS } from "../fixtures/golden/manifests.js";
import { MCPManifestSchema, applyRules, SENTINEL_QUICK_RULES, SENTINEL_DEEP_RULES } from "../../src/lib/sentinel-rules.js";
describe("existing Sentinel findings", () => {
  for (const [name, input] of Object.entries(GOLDEN_MANIFESTS)) it(name, () => {
    const m = MCPManifestSchema.parse(input);
    const old = (rules: typeof SENTINEL_QUICK_RULES) => applyRules(m, rules).filter(f => /^S-0(?:0[1-9]|1\d|2[0-6])$/.test(f.rule_id));
    expect({ quick: old(SENTINEL_QUICK_RULES), deep: old(SENTINEL_DEEP_RULES) }).toEqual(expected[name as keyof typeof expected]);
  });
});

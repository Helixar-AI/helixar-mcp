import { writeFileSync } from "node:fs";
import { MCPManifestSchema, applyRules, SENTINEL_QUICK_RULES, SENTINEL_DEEP_RULES } from "../src/lib/sentinel-rules.js";
import { GOLDEN_MANIFESTS } from "../tests/fixtures/golden/manifests.js";
const output = Object.fromEntries(Object.entries(GOLDEN_MANIFESTS).map(([name, value]) => {
  const manifest = MCPManifestSchema.parse(value);
  return [name, { quick: applyRules(manifest, SENTINEL_QUICK_RULES), deep: applyRules(manifest, SENTINEL_DEEP_RULES) }];
}));
writeFileSync(new URL("../tests/fixtures/golden/expected.json", import.meta.url), JSON.stringify(output, null, 2) + "\n");

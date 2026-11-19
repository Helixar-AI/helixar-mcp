import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { TRIFECTA_RULES } from "./trifecta.js";
import { refsFor } from "./taxonomy.js";
import { SENTINEL_DEEP_RULES } from "./sentinel-rules.js";

export function catalogList() {
  return [...SENTINEL_DEEP_RULES, ...TRIFECTA_RULES].map(({ id, severity, category, mode, title }) =>
    ({ id, severity, category, mode, title, refs: refsFor(id) }));
}

export function catalogEntry(id: string) {
  const rule = [...SENTINEL_DEEP_RULES, ...TRIFECTA_RULES].find((entry) => entry.id === id);
  if (!rule) throw new McpError(-32002, "Resource not found");
  const { severity, category, mode, title, description, remediation, source } = rule;
  const refs = refsFor(id);
  return { id, severity, category, mode, title, description, remediation, source, refs };
}

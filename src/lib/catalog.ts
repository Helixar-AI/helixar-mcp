import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { SENTINEL_DEEP_RULES } from "./sentinel-rules.js";

export function catalogList() {
  return SENTINEL_DEEP_RULES.map(({ id, severity, category, mode, title, refs }) =>
    ({ id, severity, category, mode, title, refs }));
}

export function catalogEntry(id: string) {
  const rule = SENTINEL_DEEP_RULES.find((entry) => entry.id === id);
  if (!rule) throw new McpError(-32002, "Resource not found");
  const { severity, category, mode, title, description, remediation, source, refs } = rule;
  return { id, severity, category, mode, title, description, remediation, source, refs };
}

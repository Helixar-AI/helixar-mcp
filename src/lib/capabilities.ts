import { effectiveSchema } from "./manifest-schema-strings.js";
import type { MCPTool } from "./sentinel-rules.js";

export type Capability = "private_data" | "untrusted_input" | "exfil_channel";

/** Classify explicit terms only. Underscores and hyphens delimit words in tool
 * names/descriptions; no stemming, camel-case splitting, or schema-value scan. */
export function classify(tool: MCPTool): Set<Capability> {
  const text = `${tool.name} ${tool.description}`.replace(/[_-]+/g, " ").toLowerCase();
  const schema = effectiveSchema(tool);
  const properties = schema && typeof schema === "object" && !Array.isArray(schema)
    ? (schema as { properties?: unknown }).properties : undefined;
  const names = new Set(properties && typeof properties === "object" && !Array.isArray(properties)
    ? Object.keys(properties).map(name => name.toLowerCase()) : []);
  const has = (pattern: RegExp) => pattern.test(text);
  const hasProperty = (...keys: string[]) => keys.some(key => names.has(key));
  const capabilities = new Set<Capability>();
  if (has(/\b(ssn|social security|dob|date of birth|passport|credit card|card number|pii|customer|patient|salary|credential|password|secret|api ?key|token|private key)\b/) ||
      (has(/\b(read|get|list|query|search|export|dump|download)\b/) && has(/\b(file|database|db|table|record|email|inbox|message|crm|contact)\b/)) || hasProperty("sql", "query")) capabilities.add("private_data");
  if ((has(/\b(fetch|browse|scrape|crawl|read|get|search)\b/) && has(/\b(url|web|page|email|inbox|message|issue|ticket|comment|chat|rss|feed)\b/)) || hasProperty("url", "uri", "endpoint", "link")) capabilities.add("untrusted_input");
  if (has(/\b(send|post|publish|upload|notify|email|message|share|webhook|callback|forward)\b/) || hasProperty("webhook", "callback", "notify_url", "callback_url") ||
      (has(/\b(write|save|create|put)\b/) && has(/\b(file|path)\b/))) capabilities.add("exfil_channel");
  return capabilities;
}

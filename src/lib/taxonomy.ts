/** Source versions and retrieval date used to curate the mappings below. */
export const TAXONOMY_SOURCES = {
  owasp_llm: { name: "OWASP Top 10 for LLM Applications 2025", url: "https://genai.owasp.org/llm-top-10/", retrieved: "2026-11-17" },
  owasp_agentic: { name: "OWASP Top 10 for Agentic Applications 2026", url: "https://genai.owasp.org/download/52117/?tmstv=1765059207", published: "2025-12", retrieved: "2026-11-17" },
  mitre_atlas: { name: "MITRE ATLAS 5.6.0", url: "https://raw.githubusercontent.com/mitre-atlas/atlas-data/v5.6.0/dist/ATLAS.yaml", retrieved: "2026-11-17" },
} as const;
export interface RuleRefs { owasp_llm?: string[]; owasp_agentic?: string[]; mitre_atlas?: string[] }
export const ALLOWED_IDS = {
  owasp_llm: Array.from({ length: 10 }, (_, i) => `LLM${String(i + 1).padStart(2, "0")}:2025`),
  owasp_agentic: Array.from({ length: 10 }, (_, i) => `ASI${String(i + 1).padStart(2, "0")}`),
  mitre_atlas: ["AML.T0055", "AML.T0101", "AML.T0086", "AML.T0057", "AML.T0051", "AML.T0110", "AML.T0050", "AML.T0053", "AML.T0098", "AML.T0068"],
} as const;
const refs = (llm: string[], agentic: string[] = [], atlas: string[] = []): RuleRefs => ({
  ...(llm.length && { owasp_llm: llm.map(id => `${id}:2025`) }),
  ...(agentic.length && { owasp_agentic: agentic }),
  ...(atlas.length && { mitre_atlas: atlas }),
});
export const RULE_REFS: Record<string, RuleRefs> = {};
function map(ids: string, value: RuleRefs) { for (const id of ids.split(" ")) RULE_REFS[id] = value; }
map("S-001 S-006", refs(["LLM06"], ["ASI03"]));
map("S-002 S-020 S-021", refs(["LLM06"], ["ASI03"]));
map("S-003 S-005", refs(["LLM02"], ["ASI03"], ["AML.T0055"]));
map("S-004", refs(["LLM06"], ["ASI02"], ["AML.T0101"]));
map("S-007 S-022", refs(["LLM02"], ["ASI02"], ["AML.T0086"]));
map("S-008", refs(["LLM02"], [], ["AML.T0057"]));
map("S-009 S-017", refs(["LLM10"]));
map("S-010 S-028", refs(["LLM01"], ["ASI01"], ["AML.T0051", "AML.T0110"]));
map("S-011 S-015", refs(["LLM05"], ["ASI05"], ["AML.T0050"]));
map("S-012", refs(["LLM05"]));
map("S-013 S-014 S-024 S-025", refs(["LLM03"], ["ASI04"]));
map("S-016", refs(["LLM01"], ["ASI01"], ["AML.T0051"]));
map("S-018", refs(["LLM06"]));
map("S-019", refs([], ["ASI02"]));
map("S-023", refs(["LLM06"], ["ASI02"], ["AML.T0053"]));
map("S-026", refs(["LLM02"], ["ASI03"], ["AML.T0098"]));
map("S-027 S-030", refs(["LLM01"], ["ASI01"], ["AML.T0068"]));
map("S-029", refs(["LLM01"], ["ASI02"], ["AML.T0110"]));
map("S-031", refs(["LLM01"], ["ASI01"], ["AML.T0110"]));
map("S-032", refs(["LLM06"], ["ASI02", "ASI09"]));
map("T-001 T-002", refs(["LLM02", "LLM06"], ["ASI02"], ["AML.T0086"]));
map("T-003", refs([], ["ASI02", "ASI04"]));
/** Return a fresh mapping so callers cannot mutate the shared catalog. */
export function refsFor(id: string): RuleRefs {
  const value = RULE_REFS[id];
  if (!value) return {};
  return Object.fromEntries(Object.entries(value).map(([key, ids]) => [key, [...ids]]));
}

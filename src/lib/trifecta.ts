import { classify, type Capability } from "./capabilities.js";
import { detectShadowing, escapeEvidence } from "./poisoning.js";
import type { MCPManifest, RuleFinding, Severity } from "./sentinel-rules.js";
import { refsFor } from "./taxonomy.js";

const source = "Simon Willison, The lethal trifecta for AI agents (2025): " +
  "https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/";

const sameServer = {
  id: "T-001",
  title: "Combined capabilities on one server",
  severity: "critical",
  description: "A server combines private data access, untrusted input, and an external output channel.",
  remediation: "Separate these capabilities and restrict access to sensitive data and external outputs.",
} as const;
const crossServer = {
  id: "T-002",
  title: "Combined capabilities across servers",
  severity: "critical",
  description: "The servers together combine private data access, untrusted input, and an external output channel.",
  remediation: "Separate access to sensitive data from untrusted inputs and external outputs across servers.",
} as const;
const duplicateNames = {
  id: "T-003",
  title: "Duplicate tool names across servers",
  severity: "high",
  description: "Multiple servers expose a tool with the same name.",
  remediation: "Use distinct tool names and verify which server owns each tool.",
} as const;

export const TRIFECTA_RULES = [sameServer, crossServer, duplicateNames].map((rule) => ({
  ...rule,
  category: "composition" as const,
  mode: "deep" as const,
  source,
}));

interface Entry {
  label: string;
  manifest: MCPManifest;
}

type Witnesses = Map<Capability, { label: string; tool: string }>;
const tags: Capability[] = ["private_data", "untrusted_input", "exfil_channel"];

function witnesses({ label, manifest }: Entry): Witnesses {
  const result: Witnesses = new Map();
  for (const tool of manifest.tools) {
    for (const tag of classify(tool)) {
      if (!result.has(tag)) result.set(tag, { label, tool: tool.name });
    }
    if (result.size === tags.length) break;
  }
  return result;
}

function describeWitnesses(items: Witnesses): string {
  return tags.map((tag) => {
    const { label, tool } = items.get(tag)!;
    return `${tag}: ${escapeEvidence(label)} / ${escapeEvidence(tool)}`;
  }).join(" | ");
}

function finding(
  rule: { id: string; severity: Severity; description: string; remediation: string },
  evidence: string,
): RuleFinding {
  return {
    rule_id: rule.id,
    severity: rule.severity,
    category: "composition",
    description: rule.description,
    remediation: rule.remediation,
    evidence,
    refs: refsFor(rule.id),
  };
}

export function singleServer(manifest: MCPManifest, label = manifest.name): RuleFinding[] {
  const items = witnesses({ manifest, label });
  return items.size === tags.length ? [finding(sameServer, describeWitnesses(items))] : [];
}

export function combined(entries: Entry[]): RuleFinding[] {
  const results: RuleFinding[] = [];
  const all: Witnesses = new Map();
  let allOnOneServer = false;
  const owners = new Map<string, Entry[]>();

  for (const entry of entries) {
    const local = witnesses(entry);
    allOnOneServer ||= local.size === tags.length;
    for (const [tag, witness] of local) {
      if (!all.has(tag)) all.set(tag, witness);
    }
    for (const name of new Set(entry.manifest.tools.map((tool) => tool.name))) {
      const entriesForTool = owners.get(name) ?? [];
      entriesForTool.push(entry);
      owners.set(name, entriesForTool);
    }
  }
  if (all.size === tags.length && !allOnOneServer) {
    results.push(finding(crossServer, describeWitnesses(all)));
  }

  for (const [name, toolOwners] of owners) {
    if (toolOwners.length > 1) {
      const labels = toolOwners.map(({ label }) => escapeEvidence(label)).join(", ");
      results.push(finding(duplicateNames, `${escapeEvidence(name)}: ${labels}`));
    }
  }

  for (const entry of entries) {
    const otherNames = [...owners].filter(([, toolOwners]) =>
      toolOwners.length > 1 || toolOwners[0] !== entry).map(([name]) => name);
    if (detectShadowing(entry.manifest, otherNames)) {
      results.push(finding({
        id: "S-029",
        severity: "high",
        description: "A tool description directs the caller to use a tool from another server.",
        remediation: "Remove directions that alter the caller's use of other tools.",
      }, `Server: ${escapeEvidence(entry.label)}`));
    }
  }
  return results;
}

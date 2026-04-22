// Sentinel detection rules — public surface only.
//
// IMPORTANT (per spec §6 IP protection):
//   - Public rule descriptions and remediation guidance only.
//   - No implementation thresholds, sequence patterns, FP-demotion logic,
//     or anything that would let a reader reproduce the proprietary
//     Sentinel internals.
//   - Each rule is a self-contained pure function.
//
// SENTINEL_QUICK_RULES is the top-8 set used by the authless quick mode
// of helixar_inspect_mcp. Phase 5 adds the remaining 18 rules and
// exports SENTINEL_DEEP_RULES.

import { z } from "zod";

// ───────────────────────────────────────────────────────────────────────────
// Manifest shape
// ───────────────────────────────────────────────────────────────────────────

export const MCPToolSchema = z.object({
  name: z.string(),
  description: z.string().default(""),
  parameters: z.unknown().optional(),
  destructive: z.boolean().optional(),
  requires_confirmation: z.boolean().optional(),
});

export const MCPManifestSchema = z.object({
  name: z.string(),
  version: z.string().default("0.0.0"),
  tools: z.array(MCPToolSchema).default([]),
  transport: z.enum(["http", "https", "stdio", "sse"]).optional(),
  auth: z
    .object({
      type: z.string().optional(),
      scopes: z.array(z.string()).optional(),
    })
    .optional(),
  rate_limit: z
    .object({
      requests_per_minute: z.number().optional(),
      requests_per_hour: z.number().optional(),
    })
    .optional(),
});

export type MCPTool = z.infer<typeof MCPToolSchema>;
export type MCPManifest = z.infer<typeof MCPManifestSchema>;

// ───────────────────────────────────────────────────────────────────────────
// Rule shape + categories
// ───────────────────────────────────────────────────────────────────────────

export type Severity = "low" | "medium" | "high" | "critical";

export type SentinelCategory =
  | "authentication"
  | "authorization"
  | "data_exfiltration"
  | "injection"
  | "supply_chain"
  | "behavioral";

export interface RuleCheckResult {
  triggered: boolean;
  evidence?: string;
}

export interface SentinelRule {
  id: string;
  severity: Severity;
  category: SentinelCategory;
  description: string;
  remediation: string;
  /** quick-mode rules ship in the top-8 set; deep-mode rules ship later. */
  mode: "quick" | "deep";
  check: (manifest: MCPManifest) => RuleCheckResult;
}

export interface RuleFinding {
  rule_id: string;
  severity: Severity;
  category: SentinelCategory;
  description: string;
  remediation: string;
  evidence?: string;
}

// ───────────────────────────────────────────────────────────────────────────
// Helpers — kept tiny and obvious; no proprietary scoring lives here.
// ───────────────────────────────────────────────────────────────────────────

function lowerHaystack(manifest: MCPManifest): string {
  // A flat lower-cased searchable view of the manifest's text surfaces.
  // Used by descriptive checks (PII keywords, prompt-injection phrasing).
  const parts: string[] = [];
  for (const tool of manifest.tools) {
    parts.push(tool.name.toLowerCase());
    parts.push((tool.description ?? "").toLowerCase());
  }
  return parts.join(" \n ");
}

function looksDestructive(tool: MCPTool): boolean {
  const verbs = ["delete", "drop", "remove", "destroy", "purge", "wipe", "truncate"];
  const nameLc = tool.name.toLowerCase();
  const descLc = (tool.description ?? "").toLowerCase();
  return verbs.some((v) => nameLc.includes(v) || descLc.includes(v));
}

function looksUnboundedExport(tool: MCPTool): boolean {
  const nameLc = tool.name.toLowerCase();
  const descLc = (tool.description ?? "").toLowerCase();
  // Heuristic: any tool name or description that mentions exporting + an
  // "everything" qualifier (all / every / entire / dump) without a row cap.
  const exportish = /\b(export|dump|download)\b/.test(nameLc) ||
    /\b(export|dump|download)\b/.test(descLc);
  const everything = /\b(all|every|entire)\b/.test(nameLc) ||
    /\b(all|every|entire)\b/.test(descLc);
  return exportish && everything;
}

const PII_KEYWORDS = [
  "ssn",
  "social_security",
  "date_of_birth",
  "dob",
  "passport",
  "credit_card",
  "card_number",
  "address",
  "phone_number",
];

const PROMPT_INJECTION_PATTERNS = [
  "ignore all previous instructions",
  "ignore previous instructions",
  "disregard the above",
  "override the system prompt",
  "you must always",
  "without confirmation",
  "unconditionally",
];

// ───────────────────────────────────────────────────────────────────────────
// The 8 quick-mode rules
// ───────────────────────────────────────────────────────────────────────────

const S_001: SentinelRule = {
  id: "S-001",
  severity: "critical",
  category: "authentication",
  mode: "quick",
  description:
    "Server exposes tools with no authentication declared. Any caller — including unrelated agents — can invoke every tool.",
  remediation:
    "Declare an auth block (api_key, oauth2, or mtls) and refuse unauthenticated requests at the transport layer.",
  check: (m) => {
    const triggered = !m.auth || !m.auth.type;
    return triggered ? { triggered, evidence: "manifest.auth missing or empty" } : { triggered };
  },
};

const S_002: SentinelRule = {
  id: "S-002",
  severity: "high",
  category: "authentication",
  mode: "quick",
  description:
    "OAuth scopes are over-broad (wildcard or top-level). The principle of least privilege is violated and a token leak grants every capability.",
  remediation:
    "Replace wildcard scopes with the narrowest set required per tool. Use a separate scope per destructive operation.",
  check: (m) => {
    const scopes = m.auth?.scopes ?? [];
    const wildcard = scopes.some((s) => s === "*" || s.endsWith(":*") || s === "all");
    return wildcard
      ? { triggered: true, evidence: `wildcard scope present: ${scopes.join(", ")}` }
      : { triggered: false };
  },
};

const S_003: SentinelRule = {
  id: "S-003",
  severity: "high",
  category: "authentication",
  mode: "quick",
  description:
    "Server transport is plain HTTP. Bearer tokens and tool payloads are exposed on the wire to any party between caller and server.",
  remediation:
    "Move the listener behind TLS (HTTPS or HTTPS-fronted reverse proxy). Reject plaintext upgrades.",
  check: (m) => {
    const triggered = m.transport === "http";
    return triggered ? { triggered, evidence: "transport=http" } : { triggered };
  },
};

const S_004: SentinelRule = {
  id: "S-004",
  severity: "high",
  category: "authorization",
  mode: "quick",
  description:
    "A destructive tool (delete / drop / purge / wipe) is invokable without an explicit confirmation flag.",
  remediation:
    "Require a typed confirmation parameter (e.g. confirm_token: 'DELETE') and validate server-side before executing.",
  check: (m) => {
    const offenders = m.tools.filter(
      (t) => looksDestructive(t) && !t.requires_confirmation,
    );
    return offenders.length > 0
      ? {
          triggered: true,
          evidence: `${offenders.length} destructive tool(s) without confirmation: ${offenders
            .map((o) => o.name)
            .join(", ")}`,
        }
      : { triggered: false };
  },
};

const S_007: SentinelRule = {
  id: "S-007",
  severity: "high",
  category: "data_exfiltration",
  mode: "quick",
  description:
    "An export-style tool returns an unbounded set of records (no row cap, no time window).",
  remediation:
    "Cap export tools to a maximum row count and require a time window. Prefer paginated retrieval for large data sets.",
  check: (m) => {
    const offenders = m.tools.filter((t) => looksUnboundedExport(t));
    return offenders.length > 0
      ? {
          triggered: true,
          evidence: `unbounded export tool(s): ${offenders.map((o) => o.name).join(", ")}`,
        }
      : { triggered: false };
  },
};

const S_008: SentinelRule = {
  id: "S-008",
  severity: "high",
  category: "data_exfiltration",
  mode: "quick",
  description:
    "A tool surfaces personally-identifiable information by name (SSN, DOB, full address, card numbers).",
  remediation:
    "Filter PII at the tool boundary. Return tokenised or redacted views; serve raw PII only behind a stricter scope.",
  check: (m) => {
    const haystack = lowerHaystack(m);
    const matched = PII_KEYWORDS.filter((k) => haystack.includes(k));
    return matched.length > 0
      ? { triggered: true, evidence: `PII keywords surfaced: ${matched.join(", ")}` }
      : { triggered: false };
  },
};

const S_010: SentinelRule = {
  id: "S-010",
  severity: "high",
  category: "injection",
  mode: "quick",
  description:
    "A tool description contains prompt-injection phrasing aimed at the calling model (e.g. 'ignore previous instructions').",
  remediation:
    "Strip or sanitise tool descriptions before they reach the model. Reject manifests whose descriptions look like instructions.",
  check: (m) => {
    const haystack = lowerHaystack(m);
    const hits = PROMPT_INJECTION_PATTERNS.filter((p) => haystack.includes(p));
    return hits.length > 0
      ? { triggered: true, evidence: `injection-shaped phrase(s): ${hits.join(" | ")}` }
      : { triggered: false };
  },
};

const S_017: SentinelRule = {
  id: "S-017",
  severity: "medium",
  category: "behavioral",
  mode: "quick",
  description:
    "No rate limiting is declared. A misbehaving or rogue caller can saturate the server, exhausting upstream provider quotas.",
  remediation:
    "Declare per-principal request budgets at the manifest layer and enforce them at the transport.",
  check: (m) => {
    const triggered = !m.rate_limit ||
      (m.rate_limit.requests_per_minute === undefined &&
        m.rate_limit.requests_per_hour === undefined);
    return triggered ? { triggered, evidence: "manifest.rate_limit missing" } : { triggered };
  },
};

export const SENTINEL_QUICK_RULES: SentinelRule[] = [
  S_001,
  S_002,
  S_003,
  S_004,
  S_007,
  S_008,
  S_010,
  S_017,
];

// ───────────────────────────────────────────────────────────────────────────
// Apply — runs a rule set and returns RuleFinding[] for triggered rules.
// ───────────────────────────────────────────────────────────────────────────

export function applyRules(manifest: MCPManifest, ruleSet: SentinelRule[]): RuleFinding[] {
  const findings: RuleFinding[] = [];
  for (const rule of ruleSet) {
    const result = rule.check(manifest);
    if (result.triggered) {
      findings.push({
        rule_id: rule.id,
        severity: rule.severity,
        category: rule.category,
        description: rule.description,
        remediation: rule.remediation,
        ...(result.evidence ? { evidence: result.evidence } : {}),
      });
    }
  }
  return findings;
}

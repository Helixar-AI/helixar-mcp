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
// of helixar_inspect_mcp. SENTINEL_DEEP_RULES is the full 26-rule set
// (8 quick + 18 deep) used by the authenticated deep mode.

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
// Deep-mode rule helpers (heuristics kept deliberately coarse — the
// proprietary sequence / weighting logic lives outside this file).
// ───────────────────────────────────────────────────────────────────────────

function paramsText(tool: MCPTool): string {
  if (tool.parameters === undefined || tool.parameters === null) return "";
  try {
    return JSON.stringify(tool.parameters).toLowerCase();
  } catch {
    return "";
  }
}

function manifestText(m: MCPManifest): string {
  const parts: string[] = [m.name.toLowerCase()];
  for (const t of m.tools) {
    parts.push(t.name.toLowerCase());
    parts.push((t.description ?? "").toLowerCase());
    parts.push(paramsText(t));
  }
  return parts.join(" \n ");
}

const CREDENTIAL_QUERY_PATTERNS = [
  /\bapi[_-]?key=/i,
  /\baccess[_-]?token=/i,
  /\bauth[_-]?token=/i,
  /\btoken=[^&\s]*[a-z]/i,
  /\?key=[a-z0-9]/i,
];

const NO_AUTH_PHRASES = [
  "no authentication",
  "no auth required",
  "public endpoint",
  "unauthenticated",
];

const LIST_ALL_PREFIXES = /^(list|fetch|get|dump|retrieve|export)_(all|every|everything)\b/;
const LIST_PREFIX = /^list_[a-z]/;

const PAGINATION_KEYS = ["limit", "page_size", "pagesize", "cursor", "offset", "page_token"];

// Narrowed to unambiguously shell/SQL-shaped parameter names. Bare
// "cmd"/"command" were dropped because they collide with legitimate
// non-shell uses (state-machine actions, device control verbs). Callers
// who genuinely expose shell input still match via the explicit
// "shell_cmd" / "bash" / "exec" / "shell" slots.
const RAW_QUERY_PARAM_NAMES = [
  '"sql"',
  '"raw_sql"',
  '"raw_query"',
  '"shell"',
  '"shell_cmd"',
  '"bash"',
  '"exec"',
];

const UNESCAPED_OUTPUT_PHRASES = [
  "raw html",
  "unescaped",
  "passthrough markdown",
  "verbatim html",
  "raw markdown",
];

const UNPINNED_PACKAGE_PHRASES = [
  "npm install",
  "pip install",
  "latest version",
  "requires package",
  "pull the latest",
];

const DEV_ENDPOINT_PHRASES = [
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "ngrok",
  ".local",
  ".test",
];

const DYNAMIC_EXEC_PATTERNS = [
  /\bexec\(/,
  /\brun_code\b/,
  /\bshell_exec\b/,
  /\bexecute_script\b/,
  /\beval\b/,
];

const ARBITRARY_FETCH_PHRASES = [
  "any url",
  "arbitrary url",
  "fetch any",
  "user-provided url",
  "caller-supplied url",
  "url supplied by the caller",
];

const PRIVILEGED_NAME_PATTERNS = [
  /\badmin_/,
  /\broot_/,
  /\bsudo_/,
  /\bimpersonate\b/,
  /\bsuper_/,
];

// Webhook / callback indicators. `"forward to"` was removed because it
// is common English phrasing (`"forward to the next step"`, `"forward to
// the agent"`) and triggered on non-webhook descriptions. `"callback
// endpoint"` is a tighter replacement signal.
const CALLBACK_PHRASES = [
  "webhook",
  "callback url",
  "callback endpoint",
  "post to url",
  "relay to",
];

const FS_NAME_PATTERNS = [
  /\bread_file\b/,
  /\bwrite_file\b/,
  /\bdelete_file\b/,
  /^fs_/,
];

const FS_PARAM_KEYS = ['"file_path"', '"filepath"', '"path"'];

// Credential-return regex patterns. Bare nouns like `password` / `secret`
// triggered on benign descriptions ("password policy", "secret rotation
// schedule"). Each pattern requires a return-verb ("returns", "response
// includes/contains") within a ~40-char window of a credential noun so
// unrelated mentions don't co-occur.
const CREDENTIAL_RETURN_PATTERNS: RegExp[] = [
  /\breturns?\b.{0,40}\b(password|secret|private[_-]?key|api[_-]?key|client[_-]?secret)\b/i,
  /\bresponse\s+(includes|contains)\b.{0,40}\b(password|secret|private[_-]?key|api[_-]?key|client[_-]?secret)\b/i,
];

// ───────────────────────────────────────────────────────────────────────────
// The 18 deep-mode rules
// ───────────────────────────────────────────────────────────────────────────

const S_005: SentinelRule = {
  id: "S-005",
  severity: "high",
  category: "authentication",
  mode: "deep",
  description:
    "A tool places bearer credentials or API keys in a URL query string. Tokens passed in query parameters leak into access logs, referrer headers, and proxy caches.",
  remediation:
    "Move credentials into the Authorization header or a request body. Never accept credentials in the query string.",
  check: (m) => {
    const haystack = manifestText(m);
    const hit = CREDENTIAL_QUERY_PATTERNS.find((p) => p.test(haystack));
    return hit
      ? { triggered: true, evidence: `credential-in-query pattern: ${hit}` }
      : { triggered: false };
  },
};

const S_006: SentinelRule = {
  id: "S-006",
  severity: "high",
  category: "authentication",
  mode: "deep",
  description:
    "The manifest advertises a mixed authentication surface — some tools describe themselves as public or unauthenticated while others require credentials.",
  remediation:
    "Keep the auth policy uniform across the server. If a read-only public tier is intentional, split it into a separate manifest with its own endpoint.",
  check: (m) => {
    const haystack = manifestText(m);
    const hit = NO_AUTH_PHRASES.find((p) => haystack.includes(p));
    return hit
      ? { triggered: true, evidence: `mixed-auth phrase: "${hit}"` }
      : { triggered: false };
  },
};

const S_009: SentinelRule = {
  id: "S-009",
  severity: "medium",
  category: "data_exfiltration",
  mode: "deep",
  description:
    "A list / get-all tool declares no pagination parameter. Callers can retrieve the entire dataset in one request.",
  remediation:
    "Require a pagination cursor or row cap on any list / search / bulk-read tool. Document a maximum page size.",
  check: (m) => {
    const offenders = m.tools.filter((t) => {
      const nameLc = t.name.toLowerCase();
      const isListy = LIST_ALL_PREFIXES.test(nameLc) || LIST_PREFIX.test(nameLc);
      if (!isListy) return false;
      const paramBlob = paramsText(t);
      const hasPagination = PAGINATION_KEYS.some((k) => paramBlob.includes(k));
      return !hasPagination;
    });
    return offenders.length > 0
      ? {
          triggered: true,
          evidence: `list tool(s) without pagination: ${offenders.map((o) => o.name).join(", ")}`,
        }
      : { triggered: false };
  },
};

const S_011: SentinelRule = {
  id: "S-011",
  severity: "high",
  category: "injection",
  mode: "deep",
  description:
    "A tool accepts raw SQL or shell input via a parameter (e.g. `sql`, `cmd`, `shell`). The caller is trusted to construct safe commands — a prompt-injected agent will not.",
  remediation:
    "Replace raw-string pass-through with a structured parameter schema. For queries, expose a typed field list and build the statement server-side.",
  check: (m) => {
    const offenders = m.tools.filter((t) => {
      const blob = paramsText(t);
      return RAW_QUERY_PARAM_NAMES.some((k) => blob.includes(k));
    });
    return offenders.length > 0
      ? {
          triggered: true,
          evidence: `raw query/shell parameter(s): ${offenders.map((o) => o.name).join(", ")}`,
        }
      : { triggered: false };
  },
};

const S_012: SentinelRule = {
  id: "S-012",
  severity: "medium",
  category: "injection",
  mode: "deep",
  description:
    "A tool returns unescaped HTML or markdown to the caller. Downstream renderers can be tricked into executing injected scripts or following hidden links.",
  remediation:
    "Escape or strip active markup before returning. Document the output as plain text.",
  check: (m) => {
    const haystack = manifestText(m);
    const hits = UNESCAPED_OUTPUT_PHRASES.filter((p) => haystack.includes(p));
    return hits.length > 0
      ? { triggered: true, evidence: `unescaped-output phrase(s): ${hits.join(" | ")}` }
      : { triggered: false };
  },
};

const S_013: SentinelRule = {
  id: "S-013",
  severity: "high",
  category: "supply_chain",
  mode: "deep",
  description:
    "A tool installs or resolves third-party packages at runtime without pinning a version. A compromised upstream release lands in every future call.",
  remediation:
    "Pin dependencies at build time. Remove any runtime `install`/`fetch-latest` behaviour from the tool surface.",
  check: (m) => {
    const haystack = manifestText(m);
    const hits = UNPINNED_PACKAGE_PHRASES.filter((p) => haystack.includes(p));
    return hits.length > 0
      ? { triggered: true, evidence: `unpinned package hint(s): ${hits.join(" | ")}` }
      : { triggered: false };
  },
};

const S_014: SentinelRule = {
  id: "S-014",
  severity: "medium",
  category: "supply_chain",
  mode: "deep",
  description:
    "Manifest text references a development or local-only endpoint (localhost, 127.0.0.1, ngrok, `.local`, `.test`). A production manifest should not depend on developer machines.",
  remediation:
    "Strip dev endpoints from descriptions. If the manifest is intended for local use only, mark it clearly and do not publish.",
  check: (m) => {
    const haystack = manifestText(m);
    const hits = DEV_ENDPOINT_PHRASES.filter((p) => haystack.includes(p));
    return hits.length > 0
      ? { triggered: true, evidence: `dev endpoint reference(s): ${hits.join(", ")}` }
      : { triggered: false };
  },
};

const S_015: SentinelRule = {
  id: "S-015",
  severity: "critical",
  category: "injection",
  mode: "deep",
  description:
    "A tool exposes a dynamic-execution primitive (`eval`, `exec`, `run_code`, `shell_exec`). Any prompt-injected input becomes arbitrary code.",
  remediation:
    "Remove dynamic-execution tools from the manifest. If scripting is required, sandbox it behind a restricted interpreter with a strict allowlist.",
  check: (m) => {
    const haystack = manifestText(m);
    const hit = DYNAMIC_EXEC_PATTERNS.find((p) => p.test(haystack));
    return hit
      ? { triggered: true, evidence: `dynamic-exec match: ${hit}` }
      : { triggered: false };
  },
};

const S_016: SentinelRule = {
  id: "S-016",
  severity: "medium",
  category: "supply_chain",
  mode: "deep",
  description:
    "A tool fetches arbitrary external URLs supplied by the caller. The server becomes a confused-deputy proxy to anywhere on the internet (SSRF).",
  remediation:
    "Constrain outbound URLs to a documented allowlist. Reject private ranges and metadata endpoints at the server.",
  check: (m) => {
    const haystack = manifestText(m);
    const hits = ARBITRARY_FETCH_PHRASES.filter((p) => haystack.includes(p));
    return hits.length > 0
      ? { triggered: true, evidence: `arbitrary-fetch phrase(s): ${hits.join(" | ")}` }
      : { triggered: false };
  },
};

const S_018: SentinelRule = {
  id: "S-018",
  severity: "medium",
  category: "behavioral",
  mode: "deep",
  description:
    "The manifest exposes an oversized tool surface (more than 20 tools). Large surfaces are harder to audit and harder to scope.",
  remediation:
    "Split the manifest into focused sub-servers. Group tools by trust tier so each can be authorised independently.",
  check: (m) => {
    return m.tools.length > 20
      ? { triggered: true, evidence: `tool count = ${m.tools.length}` }
      : { triggered: false };
  },
};

const S_019: SentinelRule = {
  id: "S-019",
  severity: "low",
  category: "behavioral",
  mode: "deep",
  description:
    "At least one tool ships with an empty or trivial description. Models are more likely to misuse under-documented tools.",
  remediation:
    "Give every tool a one-sentence description that states its input, its side effects, and its intended caller.",
  check: (m) => {
    const offenders = m.tools.filter((t) => (t.description ?? "").trim().length < 10);
    return offenders.length > 0
      ? {
          triggered: true,
          evidence: `tool(s) with trivial description: ${offenders.map((o) => o.name).join(", ")}`,
        }
      : { triggered: false };
  },
};

const S_020: SentinelRule = {
  id: "S-020",
  severity: "high",
  category: "authorization",
  mode: "deep",
  description:
    "A privileged-sounding tool (`admin_`, `root_`, `sudo_`, `impersonate`) is exposed without a matching restricted scope.",
  remediation:
    "Require a dedicated scope (e.g. `admin:*`) on privileged tools. Never let a read-tier token invoke them.",
  check: (m) => {
    const scopes = (m.auth?.scopes ?? []).map((s) => s.toLowerCase());
    const hasAdminScope = scopes.some((s) => s.includes("admin") || s.includes("root"));
    if (hasAdminScope) return { triggered: false };
    const offenders = m.tools.filter((t) => {
      const nameLc = t.name.toLowerCase();
      return PRIVILEGED_NAME_PATTERNS.some((p) => p.test(nameLc));
    });
    return offenders.length > 0
      ? {
          triggered: true,
          evidence: `privileged tool(s) without admin scope: ${offenders.map((o) => o.name).join(", ")}`,
        }
      : { triggered: false };
  },
};

const S_021: SentinelRule = {
  id: "S-021",
  severity: "medium",
  category: "authorization",
  mode: "deep",
  description:
    "OAuth scopes are coarse-grained — the declared scopes do not separate read from write. One scope grants every capability.",
  remediation:
    "Split scopes by verb and object (e.g. `read:messages`, `write:messages`). Assign the narrowest verb a tool can tolerate.",
  check: (m) => {
    const scopes = m.auth?.scopes ?? [];
    if (scopes.length === 0) return { triggered: false };
    const coarse = scopes.filter((s) => {
      if (s === "*" || s === "all") return false; // S-002 handles wildcards
      return !/^(read|write|admin|delete|list|create|update):/i.test(s);
    });
    return coarse.length > 0
      ? { triggered: true, evidence: `coarse scope(s): ${coarse.join(", ")}` }
      : { triggered: false };
  },
};

const S_022: SentinelRule = {
  id: "S-022",
  severity: "medium",
  category: "data_exfiltration",
  mode: "deep",
  description:
    "A tool declares an external callback or webhook. Tool output leaves the trust boundary before the caller has seen it.",
  remediation:
    "Restrict webhook targets to an allowlist. Log callbacks per-principal so unexpected destinations are catchable.",
  check: (m) => {
    const haystack = manifestText(m);
    const hits = CALLBACK_PHRASES.filter((p) => haystack.includes(p));
    return hits.length > 0
      ? { triggered: true, evidence: `callback phrase(s): ${hits.join(" | ")}` }
      : { triggered: false };
  },
};

const S_023: SentinelRule = {
  id: "S-023",
  severity: "high",
  category: "authorization",
  mode: "deep",
  description:
    "A tool offers arbitrary filesystem access (reads or writes files by caller-supplied path). Any prompt-injected path escapes the intended working set.",
  remediation:
    "Replace generic `read_file`/`write_file` surfaces with purpose-specific tools that resolve paths against a fixed root.",
  check: (m) => {
    const offenders = m.tools.filter((t) => {
      const nameLc = t.name.toLowerCase();
      const hasName = FS_NAME_PATTERNS.some((p) => p.test(nameLc));
      if (hasName) return true;
      const blob = paramsText(t);
      return FS_PARAM_KEYS.some((k) => blob.includes(k));
    });
    return offenders.length > 0
      ? {
          triggered: true,
          evidence: `filesystem tool(s): ${offenders.map((o) => o.name).join(", ")}`,
        }
      : { triggered: false };
  },
};

const S_024: SentinelRule = {
  id: "S-024",
  severity: "medium",
  category: "behavioral",
  mode: "deep",
  description:
    "Manifest version is pre-1.0 (`0.x`). The tool surface is not contractually stable and callers cannot pin confidently.",
  remediation:
    "Cut a 1.0 release once the tool surface stabilises. Use semver to signal breaking changes.",
  check: (m) => {
    return /^0\./.test(m.version)
      ? { triggered: true, evidence: `version=${m.version}` }
      : { triggered: false };
  },
};

const S_025: SentinelRule = {
  id: "S-025",
  severity: "low",
  category: "supply_chain",
  mode: "deep",
  description:
    "The manifest name has no publisher/vendor namespace. Authorship and trust attribution are ambiguous.",
  remediation:
    "Namespace the server name (e.g. `helixar/inspector`). Publish under a verified vendor identity.",
  check: (m) => {
    const name = m.name.trim();
    const hasNamespace = /[\/:\.]/.test(name) || /-/.test(name);
    return hasNamespace
      ? { triggered: false }
      : { triggered: true, evidence: `manifest name "${name}" has no namespace` };
  },
};

const S_026: SentinelRule = {
  id: "S-026",
  severity: "high",
  category: "data_exfiltration",
  mode: "deep",
  description:
    "A tool description indicates it returns credential material (private keys, secrets, passwords, API keys) in its response body.",
  remediation:
    "Remove credential-bearing tools. If a rotation workflow is needed, return references or short-lived handles, not the secrets themselves.",
  check: (m) => {
    const offenders = m.tools.filter((t) => {
      const desc = t.description ?? "";
      return CREDENTIAL_RETURN_PATTERNS.some((p) => p.test(desc));
    });
    return offenders.length > 0
      ? {
          triggered: true,
          evidence: `credential-return tool(s): ${offenders.map((o) => o.name).join(", ")}`,
        }
      : { triggered: false };
  },
};

export const SENTINEL_DEEP_RULES: SentinelRule[] = [
  ...SENTINEL_QUICK_RULES,
  S_005,
  S_006,
  S_009,
  S_011,
  S_012,
  S_013,
  S_014,
  S_015,
  S_016,
  S_018,
  S_019,
  S_020,
  S_021,
  S_022,
  S_023,
  S_024,
  S_025,
  S_026,
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

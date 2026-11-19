// helixar_inspect_mcp — scan an MCP server manifest against Sentinel rules
// and return a Claude-narrated security brief.
//
// Quick mode (default): authless, top-8 rules.
// Deep mode: requires api_key, runs all Sentinel and composition checks.

import { z } from "zod";
import { singleServer, combined } from "../lib/trifecta.js";
import { escapeEvidence } from "../lib/poisoning.js";
import { requireDeepAuth, type Mode } from "../lib/auth-gate.js";
import { narrate } from "../lib/narrate.js";
import { UNTRUSTED_INSTRUCTION, untrustedBlock } from "../lib/prompt-guard.js";
import {
  bucketRiskLevel,
  scoreFindings,
  type RiskLevel,
} from "../lib/risk-score.js";
import {
  applyRules,
  MAX_MANIFEST_DEPTH,
  exceedsDepth,
  MCPManifestSchema,
  SENTINEL_DEEP_RULES,
  SENTINEL_QUICK_RULES,
  type MCPManifest,
  type RuleFinding,
} from "../lib/sentinel-rules.js";
import { guardedFetch } from "#url-guard";

// ───────────────────────────────────────────────────────────────────────────
// Input + output shapes
// ───────────────────────────────────────────────────────────────────────────

const URL_PATTERN = /^https?:\/\//i;

export const InspectMcpInputSchema = z.object({
  target: z.string().min(1).optional().describe("MCP server URL or raw manifest JSON string"),
  targets: z.array(z.string().min(1)).min(2).max(10).optional()
    .describe("Two to ten MCP server URLs or raw manifest JSON strings, including up to three URLs"),
  mode: z.enum(["quick", "deep"]).default("quick"),
  context: z.string().optional(),
  api_key: z.string().optional(),
}).superRefine((value, ctx) => {
  if ((value.target !== undefined) === (value.targets !== undefined)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "provide exactly one of target or targets" });
  }
  if (value.targets && value.targets.filter((target) => URL_PATTERN.test(target)).length > 3) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "at most three URL targets are allowed" });
  }
});

export type InspectMcpInput = z.infer<typeof InspectMcpInputSchema>;

export type { RiskLevel };

export interface InspectMcpSuccess {
  risk_score: number;
  risk_level: RiskLevel;
  findings: RuleFinding[];
  summary: string;
  hdp_recommendation: boolean;
  hdp_reason?: string;
}

export interface InspectMcpError {
  error: "auth_required" | "invalid_target" | "deep_mode_unavailable";
  message: string;
}

type ManifestAssessment = Omit<InspectMcpSuccess, "summary">;

export interface InspectMcpMultiSuccess {
  servers: Array<(ManifestAssessment & { label: string }) | { label: string; error: string }>;
  combined: { findings: RuleFinding[]; risk_score: number; risk_level: RiskLevel; note?: string };
  summary: string;
}
export type InspectMcpOutput = InspectMcpSuccess | InspectMcpMultiSuccess | InspectMcpError;

// ───────────────────────────────────────────────────────────────────────────
// Manifest parser — accepts a URL or a raw JSON string
// ───────────────────────────────────────────────────────────────────────────

const JSON_START = /^\s*[{[]/;

// Manifest size + nesting caps. A hostile caller could pass a 100 MB JSON
// string or a 10,000-level-deep structure; either would burn CPU in
// JSON.parse, Zod's recursive validation, or paramsText()'s JSON.stringify.
const MAX_MANIFEST_BYTES = 1_048_576; // 1 MB

interface ParseSuccess {
  ok: true;
  manifest: MCPManifest;
}
interface ParseFailure {
  ok: false;
  reason: string;
}
type ParseResult = ParseSuccess | ParseFailure;

async function loadManifest(target: string): Promise<ParseResult> {
  let rawText: string;
  if (URL_PATTERN.test(target)) {
    const fetched = await guardedFetch(target, { maxBytes: MAX_MANIFEST_BYTES });
    if (!fetched.ok) {
      return { ok: false, reason: fetched.reason };
    }
    rawText = fetched.text;
  } else if (JSON_START.test(target)) {
    rawText = target;
  } else {
    return { ok: false, reason: "target is neither a URL nor a JSON manifest" };
  }

  // Size cap — apply uniformly to both branches. guardedFetch already caps
  // URL responses, but a raw JSON-string caller can still pass anything.
  if (Buffer.byteLength(rawText, "utf8") > MAX_MANIFEST_BYTES) {
    return {
      ok: false,
      reason: `manifest size exceeds ${MAX_MANIFEST_BYTES} bytes`,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: `manifest JSON parse failed: ${msg}` };
  }

  // Depth cap — applied BEFORE Zod so pathological nesting (e.g. 10k-deep
  // arrays) can't burn CPU in schema validation or downstream
  // JSON.stringify() calls.
  if (exceedsDepth(parsed, MAX_MANIFEST_DEPTH)) {
    return {
      ok: false,
      reason: `manifest JSON nesting exceeds ${MAX_MANIFEST_DEPTH} levels`,
    };
  }

  const validation = MCPManifestSchema.safeParse(parsed);
  if (!validation.success) {
    return { ok: false, reason: `manifest schema invalid: ${validation.error.issues.length} issue(s)` };
  }
  return { ok: true, manifest: validation.data };
}

// ───────────────────────────────────────────────────────────────────────────
// HDP recommendation heuristic — public, intentionally simple. Looks for
// tool names that suggest agentic chaining/delegation.
// ───────────────────────────────────────────────────────────────────────────

const CHAIN_HINTS = ["delegate", "chain", "forward", "relay", "sub_agent", "subagent", "handoff"];

function hdpRecommendation(manifest: MCPManifest, includeToolNames: boolean): { recommended: boolean; reason?: string } {
  const offenders = manifest.tools.filter((t) => {
    const name = t.name.toLowerCase();
    const desc = (t.description ?? "").toLowerCase();
    return CHAIN_HINTS.some((h) => name.includes(h) || desc.includes(h));
  });
  if (offenders.length >= 1) {
    const names = includeToolNames ? ` (${offenders.map((o) => o.name).join(", ")})` : "";
    return {
      recommended: true,
      reason:
        `Manifest exposes ${offenders.length} tool(s) that delegate or chain to other agents${names}. ` +
        `An HDP delegation chain would make the trust graph explicit and let downstream callers attenuate the scope.`,
    };
  }
  return { recommended: false };
}

function assessManifest(manifest: MCPManifest, mode: Mode, label?: string): ManifestAssessment {
  const findings = applyRules(manifest, mode === "deep" ? SENTINEL_DEEP_RULES : SENTINEL_QUICK_RULES);
  if (mode === "deep") findings.push(...singleServer(manifest, label));
  const risk_score = scoreFindings(findings);
  const { recommended, reason } = hdpRecommendation(manifest, label === undefined);
  return {
    risk_score,
    risk_level: bucketRiskLevel(risk_score),
    findings,
    hdp_recommendation: recommended,
    ...(reason ? { hdp_reason: reason } : {}),
  };
}

// ───────────────────────────────────────────────────────────────────────────
// Narrative prompt — kept short, Claude-Haiku-friendly
// ───────────────────────────────────────────────────────────────────────────

function buildNarrativePrompt(
  manifest: MCPManifest,
  findings: RuleFinding[],
  riskLevel: RiskLevel,
  context?: string,
): string {
  // `findings` carry our own rule descriptions (trusted), but the server
  // name and caller-supplied context are attacker-controllable.
  const findingsText = findings.length === 0
    ? "no findings"
    : findings
        .map((f) => `${f.rule_id} [${f.severity}] ${f.description}`)
        .join("\n");
  const contextBlock = context
    ? "\n\n" + untrustedBlock("server-context", context)
    : "";
  return [
    "You are a security analyst writing a 3-4 sentence security brief on an MCP server scan.",
    UNTRUSTED_INSTRUCTION,
    "Stay factual; reference rule IDs only when they materially aid the operator.",
    `Server name: ${untrustedBlock("server-name", manifest.name)}${contextBlock}`,
    `Risk level: ${riskLevel}`,
    `Findings:\n${findingsText}`,
    "Write the brief now.",
  ].join("\n\n");
}

// ───────────────────────────────────────────────────────────────────────────
// Main entry
// ───────────────────────────────────────────────────────────────────────────

export async function inspectMcp(input: InspectMcpInput): Promise<InspectMcpOutput> {
  const parsedInput = InspectMcpInputSchema.safeParse(input);
  if (!parsedInput.success) {
    return {
      error: "invalid_target",
      message: `input validation failed: ${parsedInput.error.issues
        .map((i) => i.message)
        .join("; ")}`,
    };
  }
  const { target, targets, mode, context, api_key } = parsedInput.data;

  const gateError = requireDeepAuth(mode, api_key);
  if (gateError) return gateError;

  if (target !== undefined) {
    const loaded = await loadManifest(target);
    if (!loaded.ok) return { error: "invalid_target", message: loaded.reason };
    const assessment = assessManifest(loaded.manifest, mode);
    const summary = await narrate(
      buildNarrativePrompt(loaded.manifest, assessment.findings, assessment.risk_level, context),
      { audience: "technical", maxTokens: 320 },
    );
    return { ...assessment, summary };
  }

  const servers: InspectMcpMultiSuccess["servers"] = [];
  const entries: Array<{ label: string; manifest: MCPManifest }> = [];
  for (const [index, inputTarget] of (targets ?? []).entries()) {
    const loaded = await loadManifest(inputTarget);
    if (!loaded.ok) {
      // Avoid reflecting raw target text or parser excerpts in multi-target errors.
      servers.push({ label: `server[${index}]`, error: "Unable to load or validate manifest" });
      continue;
    }
    const label = `server[${index}]: ${escapeEvidence(loaded.manifest.name)}`;
    entries.push({ label, manifest: loaded.manifest });
    servers.push({ label, ...assessManifest(loaded.manifest, mode, label) });
  }
  if (!entries.length) return { error: "invalid_target", message: "No target could be loaded or validated" };
  const findings = mode === "deep" ? combined(entries) : [];
  const risk_score = scoreFindings(findings);
  const risk_level = bucketRiskLevel(risk_score);
  const levels = servers.map((server) => {
    const level = "risk_level" in server ? server.risk_level : "unavailable";
    return `${untrustedBlock("server-label", server.label)}: ${level}`;
  }).join("\n");
  const uniqueFindings = new Map(findings.map((f) => [f.rule_id, f]));
  const findingText = [...uniqueFindings.values()]
    .map((f) => `${f.rule_id} [${f.severity}] ${f.description}`).join("\n") || "no combined findings";
  const prompt = [
    "Write a concise security brief for these MCP server scans.",
    UNTRUSTED_INSTRUCTION,
    `Server risk levels:\n${levels}`,
    `Combined risk level: ${risk_level}`,
    `Combined findings:\n${findingText}`,
    ...(context ? [untrustedBlock("server-context", context.slice(0, 4096))] : []),
  ].join("\n\n");
  const summary = await narrate(prompt, { audience: "technical", maxTokens: 320 });
  return {
    servers,
    combined: {
      findings,
      risk_score,
      risk_level,
      ...(mode === "quick" ? { note: "composition checks (T-001 to T-003) run in deep mode" } : {}),
    },
    summary,
  };
}

// helixar_inspect_mcp — scan an MCP server manifest against Sentinel rules
// and return a Claude-narrated security brief.
//
// Quick mode (default): authless, top-8 rules.
// Deep mode: requires api_key, runs all 26 rules.

import { z } from "zod";
import { narrate } from "../lib/narrate.js";
import {
  applyRules,
  MCPManifestSchema,
  SENTINEL_DEEP_RULES,
  SENTINEL_QUICK_RULES,
  type MCPManifest,
  type RuleFinding,
  type SentinelRule,
  type Severity,
} from "../lib/sentinel-rules.js";

// ───────────────────────────────────────────────────────────────────────────
// Input + output shapes
// ───────────────────────────────────────────────────────────────────────────

export const InspectMcpInputSchema = z.object({
  target: z.string().min(1).describe("MCP server URL or raw manifest JSON string"),
  mode: z.enum(["quick", "deep"]).default("quick"),
  context: z.string().optional(),
  api_key: z.string().optional(),
});

export type InspectMcpInput = z.infer<typeof InspectMcpInputSchema>;

export type RiskLevel = "NONE" | "LOW" | "MED" | "HIGH" | "CRIT";

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

export type InspectMcpOutput = InspectMcpSuccess | InspectMcpError;

// ───────────────────────────────────────────────────────────────────────────
// Severity → score weights
// ───────────────────────────────────────────────────────────────────────────

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 10,
  low: 5,
};

function bucketRiskLevel(score: number): RiskLevel {
  if (score === 0) return "NONE";
  if (score < 20) return "LOW";
  if (score < 50) return "MED";
  if (score < 80) return "HIGH";
  return "CRIT";
}

function scoreFindings(findings: RuleFinding[]): number {
  const raw = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHTS[f.severity] ?? 0), 0);
  return Math.min(100, raw);
}

// ───────────────────────────────────────────────────────────────────────────
// Manifest parser — accepts a URL or a raw JSON string
// ───────────────────────────────────────────────────────────────────────────

const URL_PATTERN = /^https?:\/\//i;
const JSON_START = /^\s*[{[]/;

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
    try {
      const response = await fetch(target);
      if (!response.ok) {
        return { ok: false, reason: `fetch returned ${response.status}` };
      }
      rawText = await response.text();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, reason: `fetch failed: ${msg}` };
    }
  } else if (JSON_START.test(target)) {
    rawText = target;
  } else {
    return { ok: false, reason: "target is neither a URL nor a JSON manifest" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: `manifest JSON parse failed: ${msg}` };
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

function hdpRecommendation(manifest: MCPManifest): { recommended: boolean; reason?: string } {
  const offenders = manifest.tools.filter((t) => {
    const name = t.name.toLowerCase();
    const desc = (t.description ?? "").toLowerCase();
    return CHAIN_HINTS.some((h) => name.includes(h) || desc.includes(h));
  });
  if (offenders.length >= 1) {
    const names = offenders.map((o) => o.name).join(", ");
    return {
      recommended: true,
      reason:
        `Manifest exposes ${offenders.length} tool(s) that delegate or chain to other agents (${names}). ` +
        `An HDP delegation chain would make the trust graph explicit and let downstream callers attenuate the scope.`,
    };
  }
  return { recommended: false };
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
  const findingsText = findings.length === 0
    ? "no findings"
    : findings
        .map((f) => `${f.rule_id} [${f.severity}] ${f.description}`)
        .join("\n");
  const ctx = context ? `\n\nServer context: ${context}` : "";
  return [
    "You are a security analyst writing a 3-4 sentence security brief on an MCP server scan.",
    "Stay factual; reference rule IDs only when they materially aid the operator.",
    `Server name: ${manifest.name}${ctx}`,
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
  const { target, mode, context, api_key } = parsedInput.data;

  if (mode === "deep" && !api_key?.trim()) {
    return {
      error: "auth_required",
      message: "deep mode requires an api_key — quick mode is the public/authless tier",
    };
  }

  const ruleSet: SentinelRule[] =
    mode === "deep" ? SENTINEL_DEEP_RULES : SENTINEL_QUICK_RULES;

  const loaded = await loadManifest(target);
  if (!loaded.ok) {
    return { error: "invalid_target", message: loaded.reason };
  }

  const findings = applyRules(loaded.manifest, ruleSet);
  const riskScore = scoreFindings(findings);
  const riskLevel = bucketRiskLevel(riskScore);
  const { recommended, reason } = hdpRecommendation(loaded.manifest);
  const summary = await narrate(
    buildNarrativePrompt(loaded.manifest, findings, riskLevel, context),
    { audience: "technical", maxTokens: 320 },
  );

  return {
    risk_score: riskScore,
    risk_level: riskLevel,
    findings,
    summary,
    hdp_recommendation: recommended,
    ...(reason ? { hdp_reason: reason } : {}),
  };
}

// helixar_releaseguard — MCP wrapper around Helixar-AI/ReleaseGuard.
//
// Quick / public (authless): `releaseguard check` only. Report-only, never
// writes. Returns the same shape as helixar_inspect_mcp so downstream
// tooling has a single schema family to handle.
//
// Deep / authenticated: full command set (`check`, `fix`, `harden`, `sbom`)
// gated behind a non-empty api_key. Real OAuth validation lands in
// Phase 7; for v1 any non-empty string unlocks deep.
//
// All ReleaseGuard rules live in the ReleaseGuard repo. This file does
// not re-implement any of them — it normalises the CLI's JSON output,
// scores it, and narrates it.

import { z } from "zod";
import { narrate } from "../lib/narrate.js";
import {
  runReleaseGuard,
  type ReleaseGuardCommand,
  type ReleaseGuardFinding,
  type ReleaseGuardScanResult,
  type RunResult,
} from "../lib/releaseguard-runner.js";

// ───────────────────────────────────────────────────────────────────────────
// Input + output shapes
// ───────────────────────────────────────────────────────────────────────────

export const ReleaseGuardInputSchema = z.object({
  target: z
    .string()
    .min(1)
    .describe("Filesystem path or git repo URL to scan"),
  mode: z.enum(["quick", "deep"]).default("quick"),
  command: z.enum(["check", "fix", "harden", "sbom"]).optional(),
  format: z.enum(["executive", "technical", "brief"]).default("technical"),
  api_key: z.string().optional(),
});

export type ReleaseGuardInput = z.infer<typeof ReleaseGuardInputSchema>;

export type RiskLevel = "NONE" | "LOW" | "MED" | "HIGH" | "CRIT";

export interface ReleaseGuardToolFinding {
  rule_id: string;
  severity: string;
  category: string;
  path?: string;
  line?: number;
  message: string;
  evidence?: string;
  autofixable?: boolean;
  recommended_fix?: string;
}

export interface ReleaseGuardSuccess {
  risk_score: number;
  risk_level: RiskLevel;
  findings: ReleaseGuardToolFinding[];
  summary: string;
  command: ReleaseGuardCommand;
  policy_result?: "pass" | "warn" | "fail" | "waived";
  artifact_ref?: string;
  sbom_ref?: string;
}

export interface ReleaseGuardError {
  error:
    | "auth_required"
    | "dependency_missing"
    | "invalid_target"
    | "execution_failed";
  message: string;
  stderr?: string;
}

export type ReleaseGuardOutput = ReleaseGuardSuccess | ReleaseGuardError;

// ───────────────────────────────────────────────────────────────────────────
// Severity weights — identical to helixar_inspect_mcp. Info = 0.
// ───────────────────────────────────────────────────────────────────────────

const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 40,
  high: 20,
  medium: 10,
  low: 5,
  info: 0,
};

function bucketRiskLevel(score: number): RiskLevel {
  if (score === 0) return "NONE";
  if (score < 20) return "LOW";
  if (score < 50) return "MED";
  if (score < 80) return "HIGH";
  return "CRIT";
}

function scoreFindings(findings: ReleaseGuardToolFinding[]): number {
  const raw = findings.reduce(
    (sum, f) => sum + (SEVERITY_WEIGHTS[f.severity.toLowerCase()] ?? 0),
    0,
  );
  return Math.min(100, raw);
}

function normaliseFinding(f: ReleaseGuardFinding): ReleaseGuardToolFinding {
  return {
    rule_id: f.rule_id ?? f.id,
    severity: f.severity,
    category: f.category,
    path: f.path,
    line: f.line,
    message: f.message,
    evidence: f.evidence,
    autofixable: f.autofixable,
    recommended_fix: f.recommended_fix,
  };
}

// ───────────────────────────────────────────────────────────────────────────
// Narrative prompt
// ───────────────────────────────────────────────────────────────────────────

function buildPrompt(
  target: string,
  command: ReleaseGuardCommand,
  findings: ReleaseGuardToolFinding[],
  riskLevel: RiskLevel,
  policyResult?: string,
): string {
  const findingsText =
    findings.length === 0
      ? "no findings"
      : findings
          .map((f) => `${f.rule_id} [${f.severity}] ${f.path ?? ""} ${f.message}`)
          .join("\n");
  return [
    "You are a release-engineering reviewer writing a 3-4 sentence brief on an artifact scan.",
    "Stay factual; reference rule IDs when they materially aid the reader.",
    `Target: ${target}`,
    `Command: releaseguard ${command}`,
    `Risk level: ${riskLevel}` +
      (policyResult ? `  |  Policy: ${policyResult}` : ""),
    `Findings:\n${findingsText}`,
    "Write the brief now.",
  ].join("\n\n");
}

// ───────────────────────────────────────────────────────────────────────────
// Main entry
// ───────────────────────────────────────────────────────────────────────────

export async function releaseguard(
  input: ReleaseGuardInput,
): Promise<ReleaseGuardOutput> {
  const parsed = ReleaseGuardInputSchema.safeParse(input);
  if (!parsed.success) {
    return {
      error: "invalid_target",
      message: `input validation failed: ${parsed.error.issues
        .map((i) => i.message)
        .join("; ")}`,
    };
  }
  const { target, mode, command: requestedCommand, api_key } = parsed.data;

  if (mode === "deep" && !api_key) {
    return {
      error: "auth_required",
      message: "deep mode requires an api_key — quick mode is the public/authless tier",
    };
  }

  // Quick mode is locked to `check`. Deep mode defaults to `check` when the
  // caller doesn't specify, which keeps behaviour predictable.
  const command: ReleaseGuardCommand =
    mode === "quick" ? "check" : (requestedCommand ?? "check");

  let run: RunResult;
  try {
    run = await runReleaseGuard(target, command);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { error: "execution_failed", message: msg };
  }

  if (!run.ok) {
    switch (run.reason) {
      case "binary_missing":
        return {
          error: "dependency_missing",
          message:
            "releaseguard CLI not found on PATH — install from https://github.com/Helixar-AI/ReleaseGuard",
          stderr: run.stderr,
        };
      case "execution_failed":
        return {
          error: "execution_failed",
          message: `releaseguard exited ${run.exitCode}`,
          stderr: run.stderr,
        };
      case "malformed_output":
        return {
          error: "invalid_target",
          message: "releaseguard returned non-JSON output — target may be invalid",
          stderr: run.stderr,
        };
    }
  }

  const findings = run.findings.map(normaliseFinding);
  const riskScore = scoreFindings(findings);
  const riskLevel = bucketRiskLevel(riskScore);
  const policyResult = extractPolicyResult(run.raw);

  const summary = await narrate(
    buildPrompt(target, command, findings, riskLevel, policyResult),
    { audience: parsed.data.format, maxTokens: 320 },
  );

  const success: ReleaseGuardSuccess = {
    risk_score: riskScore,
    risk_level: riskLevel,
    findings,
    summary,
    command,
  };
  if (policyResult) success.policy_result = policyResult;
  if (command === "harden" && typeof run.raw.evidence_dir === "string") {
    success.artifact_ref = run.raw.evidence_dir;
  }
  if (command === "sbom" && typeof run.raw.evidence_dir === "string") {
    success.sbom_ref = run.raw.evidence_dir;
  }
  return success;
}

function extractPolicyResult(
  raw: ReleaseGuardScanResult,
): "pass" | "warn" | "fail" | "waived" | undefined {
  const r = raw.policy_result?.result;
  if (r === "pass" || r === "warn" || r === "fail" || r === "waived") {
    return r;
  }
  return undefined;
}

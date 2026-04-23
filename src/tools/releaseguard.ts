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
  bucketRiskLevel,
  scoreFindings,
  type RiskLevel,
} from "../lib/risk-score.js";
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

export type { RiskLevel };

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
// Narrative prompt — branches on `format` so downstream audiences get a
// brief tuned to them (review S6). Exported so the tool's tests can assert
// on the prompt string directly without having to mock narrate().
// ───────────────────────────────────────────────────────────────────────────

export type PromptFormat = "executive" | "technical" | "brief";

export interface BuildPromptArgs {
  target: string;
  command: ReleaseGuardCommand;
  findings: ReleaseGuardToolFinding[];
  riskLevel: RiskLevel;
  policyResult?: string;
  format: PromptFormat;
}

export function buildPrompt(args: BuildPromptArgs): string {
  const { target, command, findings, riskLevel, policyResult, format } = args;
  const policyLine = policyResult ? `  |  Policy: ${policyResult}` : "";

  switch (format) {
    case "brief":
      return buildBriefPrompt(target, command, findings, riskLevel, policyLine);
    case "executive":
      return buildExecutivePrompt(target, command, findings, riskLevel, policyLine);
    case "technical":
    default:
      return buildTechnicalPrompt(target, command, findings, riskLevel, policyLine);
  }
}

function formatFindingsTechnical(findings: ReleaseGuardToolFinding[]): string {
  return findings.length === 0
    ? "no findings"
    : findings
        .map((f) => `${f.rule_id} [${f.severity}] ${f.path ?? ""} ${f.message}`)
        .join("\n");
}

function formatFindingsExecutive(findings: ReleaseGuardToolFinding[]): string {
  // No rule IDs, no paths — just severity + plain-English message.
  return findings.length === 0
    ? "no findings"
    : findings.map((f) => `- [${f.severity}] ${f.message}`).join("\n");
}

function buildTechnicalPrompt(
  target: string,
  command: ReleaseGuardCommand,
  findings: ReleaseGuardToolFinding[],
  riskLevel: RiskLevel,
  policyLine: string,
): string {
  return [
    "You are a release-engineering reviewer writing a 3-4 sentence brief on an artifact scan.",
    "Stay factual; reference rule IDs, paths, and line numbers when they materially aid the reader.",
    `Target: ${target}`,
    `Command: releaseguard ${command}`,
    `Risk level: ${riskLevel}${policyLine}`,
    `Findings:\n${formatFindingsTechnical(findings)}`,
    "Write the brief now.",
  ].join("\n\n");
}

function buildExecutivePrompt(
  target: string,
  command: ReleaseGuardCommand,
  findings: ReleaseGuardToolFinding[],
  riskLevel: RiskLevel,
  policyLine: string,
): string {
  return [
    "You are briefing a non-technical executive on a release-readiness scan.",
    "Write 2-3 sentences in plain business language that explain the level of risk this release carries and what the recommended next step is.",
    "The audience is non-technical — avoid jargon such as rule-ID tags like `[CVE-…]` or `[SEC-001]`, CLI flags like `--fail-on`, commit hashes or `SHA`s, and file paths or line numbers. Talk about business impact (customer trust, revenue risk, compliance exposure) rather than implementation detail.",
    `Target: ${target}`,
    `Command: releaseguard ${command}`,
    `Risk level: ${riskLevel}${policyLine}`,
    `Findings:\n${formatFindingsExecutive(findings)}`,
    "Write the executive brief now.",
  ].join("\n\n");
}

function buildBriefPrompt(
  target: string,
  command: ReleaseGuardCommand,
  findings: ReleaseGuardToolFinding[],
  riskLevel: RiskLevel,
  policyLine: string,
): string {
  return [
    "You are writing a single-sentence headline summary of a release-readiness scan.",
    "Hard limit: 250 characters. Write one sentence, no more. Lead with the risk level and the single most important finding. Omit everything else.",
    `Target: ${target}`,
    `Command: releaseguard ${command}`,
    `Risk level: ${riskLevel}${policyLine}`,
    `Findings:\n${formatFindingsTechnical(findings)}`,
    "Write the ≤250-char headline now.",
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

  if (mode === "deep" && !api_key?.trim()) {
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
    buildPrompt({
      target,
      command,
      findings,
      riskLevel,
      policyResult,
      format: parsed.data.format,
    }),
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
  const evidenceDir =
    typeof run.raw.evidence_dir === "string" && run.raw.evidence_dir.length > 0
      ? run.raw.evidence_dir
      : undefined;
  if (command === "harden" && evidenceDir) success.artifact_ref = evidenceDir;
  if (command === "sbom" && evidenceDir) success.sbom_ref = evidenceDir;
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

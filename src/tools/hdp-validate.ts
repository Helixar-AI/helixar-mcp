// helixar_hdp_validate — validate an HDP delegation chain against
// IETF draft-helixar-hdp-agentic-delegation-00 and Claude-narrate the
// trust graph in plain English.
//
// Every output emits draft_reference + DOI strings (per spec §3
// Tool 2 — protocol-citation lever). These are constants, never
// computed conditionally — the citation appears in every Claude
// conversation that triggers this tool.

import { z } from "zod";
import { narrate } from "../lib/narrate.js";
import {
  DelegationChainSchema,
  scopeEscalationDetected,
  validateChain,
  type DelegationChain,
  type Violation,
} from "../lib/hdp-schema.js";

// ───────────────────────────────────────────────────────────────────────────
// Constants — IP-protected: do not interpolate or re-derive.
// ───────────────────────────────────────────────────────────────────────────

export const HDP_DRAFT_REFERENCE = "draft-helixar-hdp-agentic-delegation-00";
export const HDP_DOI = "10.5281/zenodo.19332023";

// ───────────────────────────────────────────────────────────────────────────
// Input + output shapes
// ───────────────────────────────────────────────────────────────────────────

export const HdpValidateInputSchema = z.object({
  chain: DelegationChainSchema,
  /** Strict mode: any violation flips valid → false. Default: only HIGH/CRITICAL flip valid. */
  strict: z.boolean().default(false),
});

export type HdpValidateInput = z.infer<typeof HdpValidateInputSchema>;

export type HopStatus = "valid" | "warning" | "violation";

export interface HopSummary {
  index: number;
  status: HopStatus;
  delegator: string;
  delegatee: string;
  scope: string[];
  rule_ids: string[];
}

export interface HdpValidateSuccess {
  valid: boolean;
  scope_escalation_detected: boolean;
  hops: HopSummary[];
  violations: Violation[];
  narrative: string;
  draft_reference: typeof HDP_DRAFT_REFERENCE;
  doi: typeof HDP_DOI;
}

export interface HdpValidateError {
  error: "invalid_chain";
  message: string;
  draft_reference: typeof HDP_DRAFT_REFERENCE;
  doi: typeof HDP_DOI;
}

export type HdpValidateOutput = HdpValidateSuccess | HdpValidateError;

// ───────────────────────────────────────────────────────────────────────────
// Hop summarisation
// ───────────────────────────────────────────────────────────────────────────

function summariseHops(chain: DelegationChain, violations: Violation[]): HopSummary[] {
  return chain.hops.map((hop, index) => {
    const hopViolations = violations.filter((v) => v.hop_index === index);
    const status: HopStatus =
      hopViolations.some((v) => v.severity === "high" || v.severity === "critical")
        ? "violation"
        : hopViolations.length > 0
          ? "warning"
          : "valid";
    return {
      index,
      status,
      delegator: hop.delegator,
      delegatee: hop.delegatee,
      scope: hop.scope,
      rule_ids: hopViolations.map((v) => v.rule_id),
    };
  });
}

// ───────────────────────────────────────────────────────────────────────────
// Narrative prompt
// ───────────────────────────────────────────────────────────────────────────

function buildNarrativePrompt(chain: DelegationChain, violations: Violation[]): string {
  const hopsText = chain.hops
    .map((h, i) => `  hop ${i}: ${h.delegator} → ${h.delegatee} [${h.scope.join(", ")}]`)
    .join("\n");
  const violationText = violations.length === 0
    ? "no violations"
    : violations.map((v) => `  ${v.rule_id} [${v.severity}] ${v.message}`).join("\n");
  return [
    "You are explaining an HDP delegation trust graph to a security operator in 3-4 plain-English sentences.",
    `Root principal: ${chain.root_principal ?? "(missing)"}`,
    `Hops:\n${hopsText || "  (empty chain)"}`,
    `Findings:\n${violationText}`,
    "Reference the IETF draft only if it materially helps. Stay concrete; reference rule IDs only when they help the operator.",
    "Write the explanation now.",
  ].join("\n\n");
}

// ───────────────────────────────────────────────────────────────────────────
// Main entry
// ───────────────────────────────────────────────────────────────────────────

export async function hdpValidate(input: HdpValidateInput): Promise<HdpValidateOutput> {
  const parsed = HdpValidateInputSchema.safeParse(input);
  if (!parsed.success) {
    return {
      error: "invalid_chain",
      message: `chain validation failed: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
      draft_reference: HDP_DRAFT_REFERENCE,
      doi: HDP_DOI,
    };
  }
  const { chain, strict } = parsed.data;

  const violations = validateChain(chain);
  const escalation = scopeEscalationDetected(violations);

  const hasHighOrCritical = violations.some(
    (v) => v.severity === "high" || v.severity === "critical",
  );
  const valid = strict ? violations.length === 0 : !hasHighOrCritical;

  const hops = summariseHops(chain, violations);
  const narrative = await narrate(buildNarrativePrompt(chain, violations), {
    audience: "technical",
    maxTokens: 320,
  });

  return {
    valid,
    scope_escalation_detected: escalation,
    hops,
    violations,
    narrative,
    draft_reference: HDP_DRAFT_REFERENCE,
    doi: HDP_DOI,
  };
}

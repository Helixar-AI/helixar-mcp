// helixar_triage_alert — convert a Vigil/ATP detection payload into a
// kill-chain-staged, Claude-narrated triage brief.
//
// IP protection (per spec §6):
//   - Stage labels are public surface only (Preparation / Positioning /
//     Expansion / Objective).
//   - Severity is hard-capped at 'high' (no 'critical' on output) per
//     spec §3 Tool 3 — no autonomous enforcement on unvalidated dets.
//   - is_hunch_detection is exposed as a boolean only; no further
//     Hunch internals reach the narrative prompt.
//   - vigil_tier_reference is the public 0-4 tier label map.

import { z } from "zod";
import { narrate, type NarrateAudience } from "../lib/narrate.js";
import {
  classifyStage,
  parseAlert,
  type CappedSeverity,
  type KillChainStage,
  type NormalizedAlert,
} from "../lib/vigil-parser.js";

// ───────────────────────────────────────────────────────────────────────────
// Public Vigil tier reference (0-4) — spec §3 Tool 3
// ───────────────────────────────────────────────────────────────────────────

export const VIGIL_TIER_REFERENCE = {
  0: "Observe",
  1: "Alert",
  2: "Throttle",
  3: "Isolate",
  4: "Kill",
} as const;

export type VigilTierReference = typeof VIGIL_TIER_REFERENCE;

// ───────────────────────────────────────────────────────────────────────────
// Input + output shapes
// ───────────────────────────────────────────────────────────────────────────

export const TriageAlertInputSchema = z.object({
  payload: z.unknown(),
  format: z.enum(["executive", "technical", "brief"]).default("technical"),
});

export type TriageAlertInput = z.infer<typeof TriageAlertInputSchema>;

export interface TriageAlertSuccess {
  alert_id: string;
  stage: KillChainStage;
  severity: CappedSeverity;
  narrative: string;
  recommended_action: string;
  is_hunch_detection: boolean;
  vigil_tier_reference: VigilTierReference;
}

export interface TriageAlertError {
  error: "invalid_format" | "invalid_payload";
  message: string;
}

export type TriageAlertOutput = TriageAlertSuccess | TriageAlertError;

// ───────────────────────────────────────────────────────────────────────────
// Recommended action — public-safe mapping. No proprietary policy logic
// beyond a stage → tier-label suggestion.
// ───────────────────────────────────────────────────────────────────────────

const STAGE_RECOMMENDATIONS: Record<KillChainStage, string> = {
  Preparation:
    "Observe (tier 0). Continue collecting telemetry; no enforcement yet.",
  Positioning:
    "Alert (tier 1) and consider Throttle (tier 2) if persistence indicators continue.",
  Expansion:
    "Isolate (tier 3) — sandbox the agent in place while a human reviews.",
  Objective:
    "Kill (tier 4) is justified pending human confirmation. Escalate immediately.",
};

// ───────────────────────────────────────────────────────────────────────────
// Narrative prompt builders — three formats, three different shapes.
// ───────────────────────────────────────────────────────────────────────────

function buildPrompt(
  alert: NormalizedAlert,
  stage: KillChainStage,
  format: "executive" | "technical" | "brief",
): string {
  const indicators = alert.indicators.length > 0
    ? alert.indicators.join(", ")
    : "(no indicators)";

  switch (format) {
    case "brief":
      return [
        "Write a single sentence (≤ 200 chars) summarising this alert for a SIEM analyst.",
        `Stage: ${stage} | Severity: ${alert.severity} | Indicators: ${indicators}`,
        "Output ONLY the sentence, no preamble.",
      ].join("\n\n");

    case "executive":
      return [
        "You are briefing a CISO on an agentic-AI security alert. 3-4 plain-English sentences.",
        "Frame the business risk and recommended decision; avoid technical jargon, hex IDs, CVE refs, hashes.",
        `Kill-chain stage: ${stage}`,
        `Severity: ${alert.severity}`,
        `Recommendation: ${STAGE_RECOMMENDATIONS[stage]}`,
        "Write the executive brief now.",
      ].join("\n\n");

    case "technical":
    default:
      return [
        "You are briefing a security analyst on an agentic-AI detection. 4-5 sentences.",
        "Cover: stage assessment, the indicator pattern, recommended next investigation step.",
        `Stage: ${stage} | Severity: ${alert.severity}`,
        `Indicators: ${indicators}`,
        `Recommendation: ${STAGE_RECOMMENDATIONS[stage]}`,
        "Write the analyst brief now.",
      ].join("\n\n");
  }
}

const FORMAT_AUDIENCE: Record<"executive" | "technical" | "brief", NarrateAudience> = {
  executive: "executive",
  technical: "technical",
  brief: "brief",
};

const FORMAT_MAX_TOKENS: Record<"executive" | "technical" | "brief", number> = {
  executive: 240,
  technical: 320,
  brief: 80,
};

// ───────────────────────────────────────────────────────────────────────────
// Main entry
// ───────────────────────────────────────────────────────────────────────────

export async function triageAlert(input: TriageAlertInput): Promise<TriageAlertOutput> {
  const parsed = TriageAlertInputSchema.safeParse(input);
  if (!parsed.success) {
    return {
      error: "invalid_format",
      message: parsed.error.issues.map((i) => i.message).join("; "),
    };
  }
  const { payload, format } = parsed.data;

  const alert = parseAlert(payload);
  const stage = classifyStage(alert);
  const recommended = STAGE_RECOMMENDATIONS[stage];

  let narrative = await narrate(buildPrompt(alert, stage, format), {
    audience: FORMAT_AUDIENCE[format],
    maxTokens: FORMAT_MAX_TOKENS[format],
  });

  // Brief format: hard cap to keep SIEM consumers happy even if the model
  // overshoots. Truncate at last word boundary < limit.
  if (format === "brief" && narrative.length > 280) {
    const cut = narrative.slice(0, 277);
    const lastSpace = cut.lastIndexOf(" ");
    narrative = (lastSpace > 200 ? cut.slice(0, lastSpace) : cut) + "…";
  }

  return {
    alert_id: alert.alert_id,
    stage,
    severity: alert.severity,
    narrative,
    recommended_action: recommended,
    is_hunch_detection: alert.is_hunch_detection,
    vigil_tier_reference: VIGIL_TIER_REFERENCE,
  };
}

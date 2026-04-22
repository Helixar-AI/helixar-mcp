// Vigil / ATP detection-payload normaliser + kill-chain stage classifier.
//
// IMPORTANT (per spec §6 IP protection):
//   - Hunch Mode internals are NEVER named or described here.
//   - Stage labels are public surface only: Preparation / Positioning /
//     Expansion / Objective.
//   - Severity is hard-capped at 'high' on output — no autonomous
//     enforcement on unvalidated detections (spec §3 Tool 3).
//   - The forbidden-symbol guard test asserts that no
//     Hunch-internals tokens appear in this file.

import { z } from "zod";

// ───────────────────────────────────────────────────────────────────────────
// Public-surface types
// ───────────────────────────────────────────────────────────────────────────

export type CappedSeverity = "low" | "medium" | "high";

export type KillChainStage = "Preparation" | "Positioning" | "Expansion" | "Objective";

export interface NormalizedAlert {
  alert_id: string;
  agent_id?: string;
  severity: CappedSeverity;
  indicators: string[];
  timeline?: Array<{ at?: string; event?: string }>;
  is_hunch_detection: boolean;
  /** Loose, non-IP-leaking pass-through of the raw payload for downstream callers. */
  raw_summary?: Record<string, unknown>;
}

// Loose input — Vigil / ATP customers' payloads vary; default everything.
export const RawAlertSchema = z
  .object({
    alert_id: z.string().optional(),
    agent_id: z.string().optional(),
    severity: z.string().optional(),
    indicators: z.array(z.string()).optional(),
    timeline: z
      .array(z.object({ at: z.string().optional(), event: z.string().optional() }).passthrough())
      .optional(),
    detector_kind: z.string().optional(),
  })
  .passthrough();

export type RawAlert = z.infer<typeof RawAlertSchema>;

// ───────────────────────────────────────────────────────────────────────────
// Severity cap
// ───────────────────────────────────────────────────────────────────────────

const VALID_INPUT_SEVERITIES = new Set(["low", "medium", "high", "critical"]);

export function cappedSeverity(input: unknown): CappedSeverity {
  if (typeof input !== "string") return "medium";
  const lc = input.toLowerCase();
  if (!VALID_INPUT_SEVERITIES.has(lc)) return "medium";
  if (lc === "critical") return "high"; // hard cap — never returns 'critical'
  return lc as CappedSeverity;
}

// ───────────────────────────────────────────────────────────────────────────
// Indicator → stage classifier
// ───────────────────────────────────────────────────────────────────────────

// Public-safe keyword sets. These are descriptive labels of behaviour
// categories — not the proprietary detection sequences themselves.

const PREPARATION_KEYWORDS = [
  "scan",
  "probe",
  "recon",
  "discovery",
  "enumeration",
  "fingerprint",
];

const POSITIONING_KEYWORDS = [
  "persistence",
  "crontab",
  "autostart",
  "systemd_unit",
  "registry.run",
  "scheduled_task",
  "launchagent",
  "lateral.start",
];

const EXPANSION_KEYWORDS = [
  "escalation",
  "elevation",
  "sudoers",
  "setuid",
  "lateral.pivot",
  "credential.dump",
];

const OBJECTIVE_KEYWORDS = [
  "exfil",
  "exfiltration",
  "impact",
  "data_destruction",
  "encryption.bulk",
  "ransom",
  "objective",
];

function indicatorMatches(indicators: string[], keywords: string[]): boolean {
  const haystack = indicators.map((i) => i.toLowerCase()).join(" ");
  return keywords.some((k) => haystack.includes(k));
}

export function classifyStage(alert: NormalizedAlert): KillChainStage {
  // Order matters — we evaluate from the most-progressed stage backwards
  // so an alert with both recon and exfil indicators is classified as
  // Objective. Most-progressed wins.
  if (indicatorMatches(alert.indicators, OBJECTIVE_KEYWORDS)) return "Objective";
  if (indicatorMatches(alert.indicators, EXPANSION_KEYWORDS)) return "Expansion";
  if (indicatorMatches(alert.indicators, POSITIONING_KEYWORDS)) return "Positioning";
  if (indicatorMatches(alert.indicators, PREPARATION_KEYWORDS)) return "Preparation";
  return "Preparation";
}

// ───────────────────────────────────────────────────────────────────────────
// parseAlert
// ───────────────────────────────────────────────────────────────────────────

export function parseAlert(payload: unknown): NormalizedAlert {
  const raw = RawAlertSchema.safeParse(payload);
  const data: RawAlert = raw.success ? raw.data : { alert_id: "unknown" };

  return {
    alert_id: data.alert_id ?? "unknown",
    ...(data.agent_id ? { agent_id: data.agent_id } : {}),
    severity: cappedSeverity(data.severity),
    indicators: data.indicators ?? [],
    ...(data.timeline ? { timeline: data.timeline } : {}),
    is_hunch_detection: (data.detector_kind ?? "").toLowerCase() === "hunch",
  };
}

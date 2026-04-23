// Shared risk-scoring helpers used by every Helixar MCP tool that produces
// severity-tagged findings. Keeping this in one place guarantees the
// risk_score / risk_level contract stays stable across tools — downstream
// consumers can rely on a single weighting + bucket definition.

export type RiskLevel = "NONE" | "LOW" | "MED" | "HIGH" | "CRIT";

// `info` is present so scoreFindings() accepts info-tagged findings without
// falling through to the "unknown severity" default; it intentionally
// contributes 0 to the score.
export const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 40,
  high: 20,
  medium: 10,
  low: 5,
  info: 0,
};

export function bucketRiskLevel(score: number): RiskLevel {
  if (score === 0) return "NONE";
  if (score < 20) return "LOW";
  if (score < 50) return "MED";
  if (score < 80) return "HIGH";
  return "CRIT";
}

export function scoreFindings<T extends { severity: string }>(
  findings: T[],
): number {
  const raw = findings.reduce(
    (sum, f) => sum + (SEVERITY_WEIGHTS[f.severity.toLowerCase()] ?? 0),
    0,
  );
  return Math.min(100, raw);
}

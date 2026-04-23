import { describe, expect, it } from "vitest";
import {
  bucketRiskLevel,
  SEVERITY_WEIGHTS,
  scoreFindings,
} from "../../src/lib/risk-score.js";

describe("risk-score — bucketRiskLevel", () => {
  it("returns NONE at 0", () => {
    expect(bucketRiskLevel(0)).toBe("NONE");
  });

  it("returns LOW at the 1..19 boundaries", () => {
    expect(bucketRiskLevel(1)).toBe("LOW");
    expect(bucketRiskLevel(19)).toBe("LOW");
  });

  it("returns MED at the 20..49 boundaries", () => {
    expect(bucketRiskLevel(20)).toBe("MED");
    expect(bucketRiskLevel(49)).toBe("MED");
  });

  it("returns HIGH at the 50..79 boundaries", () => {
    expect(bucketRiskLevel(50)).toBe("HIGH");
    expect(bucketRiskLevel(79)).toBe("HIGH");
  });

  it("returns CRIT at 80 and 100", () => {
    expect(bucketRiskLevel(80)).toBe("CRIT");
    expect(bucketRiskLevel(100)).toBe("CRIT");
  });
});

describe("risk-score — scoreFindings", () => {
  it("returns 0 on empty input", () => {
    expect(scoreFindings([])).toBe(0);
  });

  it("sums lowercased severity weights and tolerates unknown severities", () => {
    const findings = [
      { severity: "CRITICAL" }, // 40 — case-insensitive
      { severity: "high" }, // 20
      { severity: "bogus" }, // 0 — unknown must not blow up
      { severity: "info" }, // 0 — info contributes nothing
    ];
    expect(scoreFindings(findings)).toBe(60);
  });

  it("caps the total at 100 even when weights exceed it", () => {
    // 4 × critical = 160 → cap at 100
    const findings = [
      { severity: "critical" },
      { severity: "critical" },
      { severity: "critical" },
      { severity: "critical" },
    ];
    expect(scoreFindings(findings)).toBe(100);
  });
});

describe("risk-score — SEVERITY_WEIGHTS", () => {
  it("exposes the canonical weights", () => {
    expect(SEVERITY_WEIGHTS).toEqual({
      critical: 40,
      high: 20,
      medium: 10,
      low: 5,
      info: 0,
    });
  });
});

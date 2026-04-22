import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  cappedSeverity,
  classifyStage,
  parseAlert,
} from "../../src/lib/vigil-parser.js";

describe("parseAlert", () => {
  it("normalises a minimal payload with sensible defaults", () => {
    const out = parseAlert({ alert_id: "alrt-1" });
    expect(out.alert_id).toBe("alrt-1");
    expect(out.severity).toBeDefined();
    expect(out.indicators).toEqual([]);
    expect(out.is_hunch_detection).toBe(false);
  });

  it("never throws on missing fields", () => {
    expect(() => parseAlert({})).not.toThrow();
  });

  it("preserves indicators when provided", () => {
    const out = parseAlert({
      alert_id: "alrt-2",
      indicators: ["process.spawn:curl", "process.spawn:bash"],
    });
    expect(out.indicators).toContain("process.spawn:curl");
  });

  it("sets is_hunch_detection from detector_kind", () => {
    const out = parseAlert({ alert_id: "alrt-3", detector_kind: "hunch" });
    expect(out.is_hunch_detection).toBe(true);
  });
});

describe("cappedSeverity — never returns critical", () => {
  it("low → low", () => {
    expect(cappedSeverity("low")).toBe("low");
  });
  it("medium → medium", () => {
    expect(cappedSeverity("medium")).toBe("medium");
  });
  it("high → high", () => {
    expect(cappedSeverity("high")).toBe("high");
  });
  it("critical → high (capped)", () => {
    expect(cappedSeverity("critical")).toBe("high");
  });
  it("unknown / undefined → medium default", () => {
    expect(cappedSeverity(undefined)).toBe("medium");
    expect(cappedSeverity("garbage")).toBe("medium");
  });
});

describe("classifyStage", () => {
  it("recon / scan / probe → Preparation", () => {
    const out = parseAlert({
      alert_id: "p1",
      indicators: ["network.scan:internal_subnet", "discovery.recon"],
    });
    expect(classifyStage(out)).toBe("Preparation");
  });

  it("persistence / cron / autostart → Positioning", () => {
    const out = parseAlert({
      alert_id: "p2",
      indicators: ["persistence:crontab.add", "autostart:systemd_unit"],
    });
    expect(classifyStage(out)).toBe("Positioning");
  });

  it("escalation / pivot → Expansion", () => {
    const out = parseAlert({
      alert_id: "p3",
      indicators: ["privilege.escalation:sudoers_modified", "lateral.pivot:ssh_outbound"],
    });
    expect(classifyStage(out)).toBe("Expansion");
  });

  it("exfiltration / impact / kill_chain.objective → Objective", () => {
    const out = parseAlert({
      alert_id: "p4",
      indicators: ["exfil:s3.upload", "impact:data_destruction"],
    });
    expect(classifyStage(out)).toBe("Objective");
  });

  it("falls back to Preparation when no indicator matches", () => {
    const out = parseAlert({ alert_id: "p5", indicators: ["something_unfamiliar"] });
    expect(classifyStage(out)).toBe("Preparation");
  });
});

describe("IP-protection guard — source contains no Hunch internals symbols", () => {
  it("vigil-parser.ts has no forbidden symbols", () => {
    const src = readFileSync("src/lib/vigil-parser.ts", "utf8").toLowerCase();
    const forbidden = [
      "iob",
      "pipeline_stage",
      "weighted_signal",
      "signal_score",
      "anomaly_weight",
      "fp_demote",
      "invariant_stage",
    ];
    for (const sym of forbidden) {
      expect(src.includes(sym), `forbidden symbol present: ${sym}`).toBe(false);
    }
  });
});

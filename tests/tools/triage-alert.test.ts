import { describe, expect, it } from "vitest";
import { triageAlert } from "../../src/tools/triage-alert.js";

describe("triageAlert — output shape", () => {
  it("returns the canonical fields regardless of format", async () => {
    const out = await triageAlert({
      payload: { alert_id: "a-1", severity: "medium", indicators: ["scan:port"] },
    });
    expect(out).toMatchObject({
      alert_id: "a-1",
      stage: expect.any(String),
      severity: expect.any(String),
      narrative: expect.any(String),
      recommended_action: expect.any(String),
      is_hunch_detection: expect.any(Boolean),
      vigil_tier_reference: expect.any(Object),
    });
  });

  it("vigil_tier_reference is the public 0-4 map", async () => {
    const out = await triageAlert({ payload: { alert_id: "a-2" } });
    expect(out.vigil_tier_reference[0]).toBe("Observe");
    expect(out.vigil_tier_reference[1]).toBe("Alert");
    expect(out.vigil_tier_reference[2]).toBe("Throttle");
    expect(out.vigil_tier_reference[3]).toBe("Isolate");
    expect(out.vigil_tier_reference[4]).toBe("Kill");
  });
});

describe("triageAlert — severity cap", () => {
  it("input severity 'critical' → output severity 'high'", async () => {
    const out = await triageAlert({
      payload: { alert_id: "a-3", severity: "critical", indicators: ["exfil:s3"] },
    });
    expect(out.severity).toBe("high");
  });
});

describe("triageAlert — stage classification", () => {
  it("Preparation when indicators are scan/recon", async () => {
    const out = await triageAlert({ payload: { alert_id: "p1", indicators: ["scan:internal"] } });
    expect(out.stage).toBe("Preparation");
  });
  it("Objective when indicators are exfil", async () => {
    const out = await triageAlert({
      payload: { alert_id: "p2", indicators: ["exfil:upload", "impact:data_destruction"] },
    });
    expect(out.stage).toBe("Objective");
  });
});

describe("triageAlert — formats", () => {
  it("brief format produces a short narrative (≤ ~250 chars)", async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const out = await triageAlert({
      payload: { alert_id: "f1", severity: "high", indicators: ["scan:internal"] },
      format: "brief",
    });
    expect(out.narrative.length).toBeLessThanOrEqual(280);
  });

  it("executive format avoids low-level technical jargon", async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const out = await triageAlert({
      payload: { alert_id: "f2", severity: "high", indicators: ["scan:internal"] },
      format: "executive",
    });
    const lower = out.narrative.toLowerCase();
    // Denylist of obviously technical tokens that shouldn't appear in a CISO summary.
    expect(lower).not.toContain("auid=");
    expect(lower).not.toContain("[cve");
    expect(lower).not.toContain("hash:");
  });

  it("technical format is allowed to be technical (smoke check only)", async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const out = await triageAlert({
      payload: { alert_id: "f3", severity: "medium", indicators: ["scan:internal"] },
      format: "technical",
    });
    expect(out.narrative.length).toBeGreaterThan(20);
  });
});

describe("triageAlert — hunch propagation", () => {
  it("is_hunch_detection true when detector_kind is hunch", async () => {
    const out = await triageAlert({
      payload: { alert_id: "h1", detector_kind: "hunch", indicators: ["scan:internal"] },
    });
    expect(out.is_hunch_detection).toBe(true);
  });

  it("is_hunch_detection false when detector_kind absent", async () => {
    const out = await triageAlert({ payload: { alert_id: "h2", indicators: ["scan:internal"] } });
    expect(out.is_hunch_detection).toBe(false);
  });
});

describe("triageAlert — input validation", () => {
  it("rejects an invalid format with a structured error", async () => {
    // @ts-expect-error - testing runtime guard
    const out = await triageAlert({ payload: { alert_id: "x" }, format: "casual" });
    expect(out).toMatchObject({ error: "invalid_format" });
  });
});

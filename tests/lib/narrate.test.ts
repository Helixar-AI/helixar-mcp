import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { narrate } from "../../src/lib/narrate.js";

describe("narrate", () => {
  let originalKey: string | undefined;

  beforeEach(() => {
    originalKey = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    vi.restoreAllMocks();
  });

  afterEach(() => {
    if (originalKey === undefined) {
      delete process.env.ANTHROPIC_API_KEY;
    } else {
      process.env.ANTHROPIC_API_KEY = originalKey;
    }
  });

  it("returns a deterministic fallback when ANTHROPIC_API_KEY is unset", async () => {
    const result = await narrate("describe a clean scan with no findings");
    expect(typeof result).toBe("string");
    expect(result.startsWith("[fallback]")).toBe(true);
    expect(result.length).toBeGreaterThan(10);
  });

  it("never throws — even when the underlying SDK throws, returns a fallback string", async () => {
    process.env.ANTHROPIC_API_KEY = "sk-ant-test-FAKE";
    // The SDK call will fail because the key is bogus; the helper must catch
    // and return a fallback rather than propagating the error.
    const result = await narrate("anything", { maxTokens: 32 });
    expect(typeof result).toBe("string");
    expect(result.startsWith("[fallback]")).toBe(true);
  });

  it("includes the prompt subject in the fallback so callers can read it", async () => {
    const result = await narrate("HDP scope escalation detected on hop 2");
    expect(result.toLowerCase()).toContain("hdp scope escalation");
  });

  it("respects an audience option in the fallback shape", async () => {
    const result = await narrate("kill-chain stage Objective", { audience: "executive" });
    expect(result.startsWith("[fallback]")).toBe(true);
    // Audience tag visible in fallback for debugging
    expect(result.toLowerCase()).toContain("executive");
  });
});

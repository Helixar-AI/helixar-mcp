import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { narrate, _resetNarrateWarning } from "../../src/lib/narrate.js";

// Hoisted mock state so `vi.mock` factories can reach it.
const mocks = vi.hoisted(() => ({
  create: vi.fn(),
}));

vi.mock("@anthropic-ai/sdk", () => {
  // Must be a real class (or `function` with `prototype`) so `new Anthropic(...)`
  // works; `vi.fn().mockImplementation(arrow)` yields a non-constructable fn.
  class AnthropicMock {
    messages = { create: mocks.create };
  }
  return { default: AnthropicMock };
});

describe("narrate", () => {
  let originalKey: string | undefined;

  beforeEach(() => {
    originalKey = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    vi.restoreAllMocks();
    mocks.create.mockReset();
    _resetNarrateWarning();
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
    mocks.create.mockRejectedValueOnce(new Error("401 unauthorized"));
    // The SDK call will fail; the helper must catch and return a fallback
    // rather than propagating the error.
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

  describe("SDK success path", () => {
    it("returns the trimmed text when the SDK resolves with a text block", async () => {
      process.env.ANTHROPIC_API_KEY = "sk-ant-test-FAKE";
      mocks.create.mockResolvedValueOnce({
        content: [{ type: "text", text: "hi there" }],
      });
      const result = await narrate("prompt");
      expect(result).toBe("hi there");
      expect(result.startsWith("[fallback]")).toBe(false);
    });

    it("trims leading/trailing whitespace on the SDK text block", async () => {
      process.env.ANTHROPIC_API_KEY = "sk-ant-test-FAKE";
      mocks.create.mockResolvedValueOnce({
        content: [{ type: "text", text: "  hi  " }],
      });
      const result = await narrate("prompt");
      expect(result).toBe("hi");
    });

    it("falls back when the SDK resolves with no text block", async () => {
      process.env.ANTHROPIC_API_KEY = "sk-ant-test-FAKE";
      mocks.create.mockResolvedValueOnce({
        content: [{ type: "tool_use", id: "toolu_123", name: "noop", input: {} }],
      });
      const result = await narrate("prompt with subject");
      expect(result.startsWith("[fallback]")).toBe(true);
      expect(result.toLowerCase()).toContain("prompt with subject");
    });

    it("does NOT fire the warn-once guard when the SDK resolves successfully", async () => {
      process.env.ANTHROPIC_API_KEY = "sk-ant-test-FAKE";
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);
      mocks.create.mockResolvedValue({
        content: [{ type: "text", text: "ok" }],
      });
      const first = await narrate("p1");
      const second = await narrate("p2");
      expect(first).toBe("ok");
      expect(second).toBe("ok");
      expect(warnSpy).not.toHaveBeenCalled();
    });
  });

  describe("_resetNarrateWarning (warn-once guard seam)", () => {
    it("is reset by _resetNarrateWarning() so a later failure warns again", async () => {
      process.env.ANTHROPIC_API_KEY = "sk-ant-test-FAKE";
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);
      mocks.create.mockRejectedValue(new Error("boom"));

      // First call: warns.
      await narrate("p1");
      expect(warnSpy).toHaveBeenCalledTimes(1);

      // Second call: warn-once guard holds.
      await narrate("p2");
      expect(warnSpy).toHaveBeenCalledTimes(1);

      // Reset seam → third call warns again.
      _resetNarrateWarning();
      await narrate("p3");
      expect(warnSpy).toHaveBeenCalledTimes(2);
    });
  });
});

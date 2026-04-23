import { describe, expect, it } from "vitest";
import { requireDeepAuth } from "../../src/lib/auth-gate.js";

describe("requireDeepAuth", () => {
  it("returns null for quick mode regardless of api_key", () => {
    expect(requireDeepAuth("quick", undefined)).toBeNull();
    expect(requireDeepAuth("quick", "")).toBeNull();
    expect(requireDeepAuth("quick", "   ")).toBeNull();
    expect(requireDeepAuth("quick", "sk-real-key")).toBeNull();
  });

  it("rejects deep mode when api_key is undefined", () => {
    const out = requireDeepAuth("deep", undefined);
    expect(out).toMatchObject({ error: "auth_required" });
    expect(out?.message.toLowerCase()).toContain("deep mode");
  });

  it("rejects deep mode when api_key is the empty string", () => {
    const out = requireDeepAuth("deep", "");
    expect(out).toMatchObject({ error: "auth_required" });
  });

  it("rejects deep mode when api_key is whitespace-only", () => {
    const out = requireDeepAuth("deep", "   \t\n");
    expect(out).toMatchObject({ error: "auth_required" });
  });

  it("returns null for deep mode when api_key is a non-empty trimmed string", () => {
    expect(requireDeepAuth("deep", "anything")).toBeNull();
    expect(requireDeepAuth("deep", "  padded  ")).toBeNull();
  });

  it("error message never leaks the supplied api_key value", () => {
    const secretish = "sk-supposed-to-be-secret";
    const out = requireDeepAuth("deep", "   ");
    expect(out?.message).not.toContain(secretish);
  });
});

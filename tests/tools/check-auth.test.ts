import { describe, expect, it, vi } from "vitest";
import { checkAuth, CheckAuthInputSchema } from "../../src/tools/check-auth.js";
vi.mock("#url-guard", () => ({ guardedFetch: vi.fn().mockResolvedValue({ ok: false, reason: "secret" }) }));

describe("checkAuth", () => {
  it("rejects non-HTTPS and URLs containing credentials", async () => {
    for (const url of ["http://example.com", "https://user:pass@example.com"]) {
      expect(CheckAuthInputSchema.safeParse({ url }).success).toBe(false);
      expect(await checkAuth({ url })).toMatchObject({ error: "invalid_url" });
    }
  });
  it("returns checks with references and a complete summary", async () => {
    const out = await checkAuth({ url: "https://example.com/mcp" });
    if (!("checks" in out)) throw new Error("expected result");
    expect(out.checks).toHaveLength(8);
    expect(Object.values(out.summary).reduce((a, b) => a + b, 0)).toBe(8);
    expect(out.checks[0]?.refs.owasp_agentic).toContain("ASI03");
    expect(out.checks[7]?.refs.owasp_llm).toContain("LLM02:2025");
    expect(JSON.stringify(out)).not.toContain("secret");
  });
});

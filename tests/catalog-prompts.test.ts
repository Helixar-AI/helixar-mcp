import { describe, expect, it } from "vitest";
import { catalogEntry, catalogList } from "../src/lib/catalog.js";
import { SENTINEL_DEEP_RULES, SENTINEL_QUICK_RULES } from "../src/lib/sentinel-rules.js";
import { reviewPrompt } from "../src/prompts/review.js";

describe("catalog and review prompt", () => {
  it("covers all rule IDs and returns rule details", () => {
    const ids = catalogList().map(r => r.id);
    for (const rule of [...SENTINEL_QUICK_RULES, ...SENTINEL_DEEP_RULES]) expect(ids).toContain(rule.id);
    expect(catalogEntry("S-027").source).toBeTruthy();
    for (const id of ["T-001", "T-002", "T-003"]) expect(catalogEntry(id)).toMatchObject({ mode: "deep", refs: expect.any(Object) });
    expect(() => catalogEntry("missing")).toThrow(expect.objectContaining({ code: -32002 }));
  });
  it("requires a target and keeps credentials out of the message", () => {
    expect(() => reviewPrompt.get({})).toThrow();
    const quick = reviewPrompt.get({ target: "example" }).messages[0]!.content.text;
    expect(quick).toContain('mode: "quick"');
    expect(quick).toContain("S-027 to S-032");
    expect(quick).toContain("example");
    expect(quick).toContain("untrusted");
    const deep = reviewPrompt.get({ target: "example", api_key: "secret-key-value" }).messages[0]!.content.text;
    expect(deep).toContain('mode: "deep"');
    expect(deep).not.toContain("secret-key-value");
  });
});

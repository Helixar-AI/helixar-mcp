import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// DNS mock — shared across the whole file. inspectMcp's URL branch now
// calls guardedFetch → node:dns/promises#lookup. Every test that hits the
// network path installs its own mockLookup.mockResolvedValueOnce(...).
const mockLookup = vi.fn();
vi.mock("node:dns/promises", () => ({
  lookup: (...args: unknown[]) => mockLookup(...args),
}));

import { inspectMcp } from "../../src/tools/inspect-mcp.js";

// Preserve + restore ANTHROPIC_API_KEY around every test so suites that
// delete it (e.g. the "[fallback]" case) can't leak into sibling files.
let originalAnthropicKey: string | undefined;
beforeEach(() => {
  originalAnthropicKey = process.env.ANTHROPIC_API_KEY;
  mockLookup.mockReset();
  vi.unstubAllGlobals();
});
afterEach(() => {
  if (originalAnthropicKey === undefined) {
    delete process.env.ANTHROPIC_API_KEY;
  } else {
    process.env.ANTHROPIC_API_KEY = originalAnthropicKey;
  }
  vi.unstubAllGlobals();
});

function makeResponse(
  status: number,
  body: string,
  headers: Record<string, string> = {},
): Response {
  const chunks = [new TextEncoder().encode(body)];
  const bodyStream = {
    async *[Symbol.asyncIterator]() {
      for (const c of chunks) yield c;
    },
  };
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: {
      get(name: string) {
        const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
        return key ? headers[key] ?? null : null;
      },
    },
    body: bodyStream,
  } as unknown as Response;
}

const cleanManifest = {
  name: "well-behaved",
  version: "1.0.0",
  transport: "https" as const,
  auth: { type: "oauth2", scopes: ["read:messages"] },
  rate_limit: { requests_per_minute: 60 },
  tools: [
    {
      name: "search",
      description: "Search messages by keyword.",
    },
  ],
};

const unsafeManifest = {
  name: "unsafe",
  version: "0.1.0",
  transport: "http" as const,
  // no auth, no rate_limit
  tools: [
    {
      name: "delete_account",
      description: "Permanently delete a user account.",
    },
    {
      name: "export_all_messages",
      description: "Download every message ever sent by every user as JSON.",
    },
  ],
};

const chainedManifest = {
  name: "chained",
  version: "1.0.0",
  transport: "https" as const,
  auth: { type: "oauth2", scopes: ["read"] },
  rate_limit: { requests_per_minute: 60 },
  tools: [
    {
      name: "delegate_to_subagent",
      description: "Delegate the task to a specialised sub-agent and forward the response.",
    },
    {
      name: "chain_call",
      description: "Chain another MCP server call and relay the result back.",
    },
  ],
};

describe("inspectMcp — quick mode", () => {
  it("returns NONE risk on a clean manifest with zero findings", async () => {
    const out = await inspectMcp({ target: JSON.stringify(cleanManifest), mode: "quick" });
    expect(out.risk_score).toBe(0);
    expect(out.risk_level).toBe("NONE");
    expect(out.findings).toEqual([]);
    expect(out.hdp_recommendation).toBe(false);
    expect(typeof out.summary).toBe("string");
  });

  it("returns multiple findings on the unsafe manifest with risk_level ≥ MED", async () => {
    const out = await inspectMcp({ target: JSON.stringify(unsafeManifest), mode: "quick" });
    expect(out.findings.length).toBeGreaterThanOrEqual(3);
    const ids = out.findings.map((f) => f.rule_id);
    expect(ids).toContain("S-001"); // no auth
    expect(ids).toContain("S-003"); // http
    expect(ids).toContain("S-004"); // destructive without confirmation
    expect(["MED", "HIGH", "CRIT"]).toContain(out.risk_level);
    expect(out.risk_score).toBeGreaterThan(0);
    expect(out.risk_score).toBeLessThanOrEqual(100);
  });

  it("derives risk_level buckets from risk_score", async () => {
    // Just one critical finding: 40 weight → HIGH bucket lower bound is 50,
    // so a single critical lands in MED. Confirms the bucketing math.
    const oneCrit = {
      ...cleanManifest,
      auth: undefined,
    };
    const out = await inspectMcp({ target: JSON.stringify(oneCrit), mode: "quick" });
    expect(out.risk_score).toBeGreaterThanOrEqual(20);
    expect(out.risk_score).toBeLessThan(50);
    expect(out.risk_level).toBe("MED");
  });

  it("flags hdp_recommendation when manifest has chaining/delegation tools", async () => {
    const out = await inspectMcp({ target: JSON.stringify(chainedManifest), mode: "quick" });
    expect(out.hdp_recommendation).toBe(true);
    expect(typeof out.hdp_reason).toBe("string");
    expect(out.hdp_reason!.length).toBeGreaterThan(10);
  });

  it("returns a structured error when deep mode is requested without an api_key", async () => {
    const out = await inspectMcp({ target: JSON.stringify(cleanManifest), mode: "deep" });
    expect(out).toMatchObject({ error: "auth_required" });
  });

  it("rejects an invalid target string with a structured parse error", async () => {
    const out = await inspectMcp({ target: "this is not json and not a url" });
    expect(out).toMatchObject({ error: "invalid_target" });
  });

  it("never throws on an unparseable manifest payload", async () => {
    const broken = '{"name": "broken", "tools": "this should be an array"}';
    const out = await inspectMcp({ target: broken });
    // Either parses with defaults or returns a structured error — both
    // acceptable, but it must not throw.
    expect(out).toBeDefined();
  });

  it("summary is a string and (in fallback mode) starts with [fallback]", async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const out = await inspectMcp({ target: JSON.stringify(unsafeManifest), mode: "quick" });
    expect(typeof out.summary).toBe("string");
    expect(out.summary?.startsWith("[fallback]")).toBe(true);
  });
});

describe("inspectMcp — URL branch (guardedFetch integration)", () => {
  it("loads a manifest over HTTPS and returns NONE for a clean fixture", async () => {
    mockLookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => makeResponse(200, JSON.stringify(cleanManifest))),
    );
    const out = await inspectMcp({ target: "https://example.com/m.json", mode: "quick" });
    expect(out).not.toMatchObject({ error: expect.anything() });
    if ("risk_level" in out) {
      expect(out.risk_level).toBe("NONE");
    }
  });

  it("returns invalid_target when fetch rejects (network error)", async () => {
    mockLookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("ECONNREFUSED");
      }),
    );
    const out = await inspectMcp({ target: "https://example.com/m.json", mode: "quick" });
    expect(out).toMatchObject({ error: "invalid_target" });
    if ("message" in out) {
      expect(out.message).toMatch(/fetch failed|ECONNREFUSED/);
    }
  });

  it("returns invalid_target with the status code on a 5xx response", async () => {
    mockLookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => makeResponse(503, "")),
    );
    const out = await inspectMcp({ target: "https://example.com/m.json", mode: "quick" });
    expect(out).toMatchObject({ error: "invalid_target" });
    if ("message" in out) {
      expect(out.message).toMatch(/fetch returned 503/);
    }
  });

  it("blocks private-IP targets before fetch is called", async () => {
    // DNS resolves the public-looking host to a loopback address.
    mockLookup.mockResolvedValue([{ address: "127.0.0.1", family: 4 }]);
    const fetchMock = vi.fn(async () => makeResponse(200, ""));
    vi.stubGlobal("fetch", fetchMock);
    const out = await inspectMcp({ target: "https://example.com/m.json", mode: "quick" });
    expect(out).toMatchObject({ error: "invalid_target" });
    if ("message" in out) {
      expect(out.message).toMatch(/blocked|private/i);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects plain-http URLs before any network/DNS call", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const out = await inspectMcp({ target: "http://example.com/m.json", mode: "quick" });
    expect(out).toMatchObject({ error: "invalid_target" });
    if ("message" in out) {
      expect(out.message).toMatch(/insecure_scheme/i);
    }
    expect(fetchMock).not.toHaveBeenCalled();
    expect(mockLookup).not.toHaveBeenCalled();
  });
});

describe("inspectMcp — manifest depth + size caps", () => {
  it("rejects a JSON string whose nesting exceeds the depth cap", async () => {
    // Build an array nested 60 levels deep: [[[[...]]]]
    let s = "0";
    for (let i = 0; i < 60; i++) s = `[${s}]`;
    const out = await inspectMcp({ target: s });
    expect(out).toMatchObject({ error: "invalid_target" });
    if ("message" in out) {
      expect(out.message).toMatch(/nesting|depth/i);
    }
  });

  it("accepts a JSON string at or below the depth cap (sanity)", async () => {
    // 10 levels deep — well under the cap. Won't validate against the
    // manifest schema, so we expect a schema error, NOT a depth error.
    let s = "0";
    for (let i = 0; i < 10; i++) s = `[${s}]`;
    const out = await inspectMcp({ target: s });
    expect(out).toMatchObject({ error: "invalid_target" });
    if ("message" in out) {
      expect(out.message).not.toMatch(/nesting|depth/i);
    }
  });

  it("rejects a JSON string larger than the size cap", async () => {
    // 2 MB payload (> 1 MB cap). Valid JSON, arbitrary structure.
    const big = "x".repeat(2 * 1024 * 1024);
    const target = JSON.stringify({ filler: big });
    const out = await inspectMcp({ target });
    expect(out).toMatchObject({ error: "invalid_target" });
    if ("message" in out) {
      expect(out.message).toMatch(/size|bytes/i);
    }
  });
});

describe("inspectMcp — deep mode", () => {
  // A manifest engineered to trip deep-only rules without tripping most
  // quick rules. Auth + TLS + rate limit are present; the tools themselves
  // invite deep-mode findings (filesystem access, dynamic exec,
  // coarse scope, pre-1.0 version, unscoped name).
  const deepOnlyManifest = {
    name: "unscoped",
    version: "0.9.0",
    transport: "https" as const,
    auth: { type: "oauth2", scopes: ["messages"] },
    rate_limit: { requests_per_minute: 60 },
    tools: [
      {
        name: "read_file",
        description: "Read any file by absolute file_path.",
      },
      {
        name: "run_code",
        description: "Execute arbitrary Python via eval().",
      },
    ],
  };

  it("returns auth_required when no api_key is supplied", async () => {
    const out = await inspectMcp({ target: JSON.stringify(deepOnlyManifest), mode: "deep" });
    expect(out).toMatchObject({ error: "auth_required" });
    // error shape — no risk fields leak out
    expect("risk_score" in out).toBe(false);
  });

  it("runs the full 26-rule set when api_key is supplied", async () => {
    const deepOut = await inspectMcp({
      target: JSON.stringify(deepOnlyManifest),
      mode: "deep",
      api_key: "anything-non-empty",
    });
    const quickOut = await inspectMcp({
      target: JSON.stringify(deepOnlyManifest),
      mode: "quick",
    });
    // Deep mode should see strictly more findings than quick on this fixture.
    if ("findings" in deepOut && "findings" in quickOut) {
      expect(deepOut.findings.length).toBeGreaterThan(quickOut.findings.length);
      const deepIds = new Set(deepOut.findings.map((f) => f.rule_id));
      // At least a couple of deep-only rule IDs must show up.
      expect(deepIds.has("S-015") || deepIds.has("S-023") || deepIds.has("S-024")).toBe(true);
    } else {
      throw new Error("deep + key should succeed");
    }
  });

  it("quick mode ignores api_key and only runs the top-8 set", async () => {
    const out = await inspectMcp({
      target: JSON.stringify(deepOnlyManifest),
      mode: "quick",
      api_key: "still-quick-please",
    });
    if ("findings" in out) {
      // None of the deep-only IDs should appear in a quick-mode run.
      const ids = out.findings.map((f) => f.rule_id);
      const deepOnlyIds = [
        "S-005", "S-006", "S-009", "S-011", "S-012", "S-013", "S-014",
        "S-015", "S-016", "S-018", "S-019", "S-020", "S-021", "S-022",
        "S-023", "S-024", "S-025", "S-026",
      ];
      for (const id of deepOnlyIds) {
        expect(ids).not.toContain(id);
      }
    } else {
      throw new Error("quick mode should succeed");
    }
  });

  it("rejects deep mode with an empty-string api_key", async () => {
    const out = await inspectMcp({
      target: JSON.stringify(deepOnlyManifest),
      mode: "deep",
      api_key: "",
    });
    expect(out).toMatchObject({ error: "auth_required" });
  });

  it("rejects deep mode with a whitespace-only api_key", async () => {
    // Review S3 parity with releaseguard: whitespace-only keys must not
    // pass the gate even though the raw string is truthy.
    const out = await inspectMcp({
      target: JSON.stringify(deepOnlyManifest),
      mode: "deep",
      api_key: "   ",
    });
    expect(out).toMatchObject({ error: "auth_required" });
  });
});

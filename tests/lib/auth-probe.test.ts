import { beforeEach, describe, expect, it, vi } from "vitest";
import { guardedFetch } from "#url-guard";
import { MAX_REQUESTS, probe } from "../../src/lib/auth-probe.js";

vi.mock("#url-guard", () => ({ guardedFetch: vi.fn() }));
const target = "https://resource.example/mcp";
const resource = "https://resource.example/.well-known/oauth-protected-resource/mcp";
const issuer = "https://auth.example/tenant";
const oauth = "https://auth.example/.well-known/oauth-authorization-server/tenant";
const headers = { "www-authenticate": `Bearer resource_metadata="${resource}"` };
const success = (status: number, text = "", h: Record<string, string> = {}) => ({ ok: true as const, status, text, headers: h });
const failure = { ok: false as const, reason: "unavailable" };
function standard() {
  vi.mocked(guardedFetch).mockImplementation(async (url, options) => {
    if (url === target && options?.method === "OPTIONS") return success(204);
    if (url === target) return success(401, "", headers);
    if (url === resource) return success(200, JSON.stringify({ resource: target, authorization_servers: [issuer, "https://third.example"] }));
    if (url === oauth) return success(200, JSON.stringify({ issuer, authorization_endpoint: "https://third.example/authorize", token_endpoint: "https://third.example/token", code_challenge_methods_supported: ["S256"], resource_parameter_supported: true }));
    return failure;
  });
}
beforeEach(() => vi.resetAllMocks());

describe("auth probe", () => {
  it("passes conformant metadata and uses only bounded safe requests", async () => {
    standard();
    const result = await probe(target);
    expect(result.checks.map((c) => c.status)).toEqual(Array(8).fill("pass"));
    expect(result.authorization_server).toBe(issuer);
    expect(result.checks[6]?.origin_validation).toBe("inferred");
    expect(guardedFetch).toHaveBeenCalledTimes(4);
    for (const [url, options] of vi.mocked(guardedFetch).mock.calls) {
      expect(url).not.toContain("third.example");
      expect(options).toMatchObject({ followRedirects: false, maxBytes: 65_536, timeoutMs: 2_500, deadlineMs: expect.any(Number) });
      expect(options?.method ?? "GET").toMatch(/^(GET|OPTIONS)$/);
    }
    expect(guardedFetch).toHaveBeenCalledWith(target, expect.objectContaining({ method: "OPTIONS", requestHeaders: { origin: "https://evil.example", accessControlRequestMethod: "POST" } }));
  });

  it("does not discover metadata for an unauthenticated server", async () => {
    vi.mocked(guardedFetch).mockResolvedValue(success(200));
    const result = await probe(target);
    expect(result.checks[0]?.status).toBe("fail");
    expect(result.checks.slice(1, 6).every((c) => c.status === "not_checked")).toBe(true);
    expect(guardedFetch).toHaveBeenCalledTimes(2);
  });

  it("flags wildcard CORS with credentials", async () => {
    standard();
    const original = vi.mocked(guardedFetch).getMockImplementation()!;
    vi.mocked(guardedFetch).mockImplementation(async (url, options) => options?.method === "OPTIONS" ? success(204, "", { "access-control-allow-origin": "*", "access-control-allow-credentials": "true" }) : original(url, options));
    expect((await probe(target)).checks[6]?.status).toBe("fail");
  });

  it("uses both OpenID fallbacks for a path issuer, never following redirects", async () => {
    standard();
    const original = vi.mocked(guardedFetch).getMockImplementation()!;
    vi.mocked(guardedFetch).mockImplementation(async (url, options) => url === oauth ? success(302, "", { location: "https://third.example/" }) : original(url, options));
    await probe(target);
    const calls = vi.mocked(guardedFetch).mock.calls.map(([url]) => url);
    expect(calls).toContain("https://auth.example/.well-known/openid-configuration/tenant");
    expect(calls).toContain("https://auth.example/tenant/.well-known/openid-configuration");
    expect(calls.some((url) => url.includes("third.example"))).toBe(false);
    expect(calls.length).toBeLessThanOrEqual(MAX_REQUESTS);
  });

  it("refuses external and insecure metadata URLs", async () => {
    for (const advertised of ["https://third.example/.well-known/x", "http://resource.example/.well-known/x"]) {
      vi.mocked(guardedFetch).mockReset();
      vi.mocked(guardedFetch).mockImplementation(async (_url, options) => options?.method === "OPTIONS" ? success(204) : success(401, "", { "www-authenticate": `Bearer resource_metadata="${advertised}"` }));
      const result = await probe(target);
      expect(guardedFetch).toHaveBeenCalledTimes(2);
      expect(result.checks[7]?.status).toBe(advertised.startsWith("http:") ? "fail" : "pass");
      expect(JSON.stringify(result)).not.toContain(advertised);
    }
  });

  it("fetches a same-origin advertised metadata path and query without exposing them", async () => {
    const advertised = "https://resource.example/custom?secret=example";
    vi.mocked(guardedFetch).mockImplementation(async (url, options) => {
      if (options?.method === "OPTIONS") return success(204);
      if (url === target) return success(401, "", { "www-authenticate": `Bearer resource_metadata="${advertised}"` });
      if (url === advertised) return success(200, JSON.stringify({ resource: target, authorization_servers: ["http://auth.example"] }));
      return failure;
    });
    const result = await probe(target);
    expect(guardedFetch).toHaveBeenCalledWith(advertised, expect.anything());
    expect(result.checks[1]?.status).toBe("pass");
    expect(result.checks[7]?.status).toBe("fail");
    expect(JSON.stringify(result)).not.toContain("secret");
  });

  it("falls back to path and root resource metadata when no URL is advertised", async () => {
    vi.mocked(guardedFetch).mockImplementation(async (url, options) => {
      if (options?.method === "OPTIONS") return success(204);
      if (url === target) return success(401);
      return failure;
    });
    const result = await probe(target);
    expect(result.checks[0]?.status).toBe("fail");
    expect(guardedFetch).toHaveBeenCalledWith(resource, expect.anything());
    expect(guardedFetch).toHaveBeenCalledWith("https://resource.example/.well-known/oauth-protected-resource", expect.anything());
  });

  it("ignores parameter-like text inside a quoted error description", async () => {
    vi.mocked(guardedFetch).mockImplementation(async (url, options) => {
      if (options?.method === "OPTIONS") return success(204);
      if (url === target) return success(401, "", { "www-authenticate": 'Bearer error_description="bad resource_metadata=https://third.example/secret"' });
      return failure;
    });
    const out = await probe(target);
    expect(out.checks[0]?.status).toBe("fail");
    expect(vi.mocked(guardedFetch).mock.calls.some(([url]) => url.includes("third.example"))).toBe(false);
  });

  it("distinguishes invalid and off-origin advertised URLs without echoing them", async () => {
    for (const advertised of ["not-a-url", "https://other.example/meta"]) {
      vi.mocked(guardedFetch).mockImplementation(async (_url, options) => options?.method === "OPTIONS" ? success(204) : success(401, "", { "www-authenticate": `Bearer resource_metadata="${advertised}"` }));
      const out = await probe(target);
      expect(out.checks[0]?.status).toBe("pass");
      expect(out.checks[1]?.evidence).toContain(advertised === "not-a-url" ? "invalid" : "outside the target origin");
      expect(JSON.stringify(out)).not.toContain(advertised);
    }
  });

  it("marks fetched malformed resource and authorization metadata as failures", async () => {
    for (const badUrl of [resource, oauth]) {
      standard();
      const original = vi.mocked(guardedFetch).getMockImplementation()!;
      vi.mocked(guardedFetch).mockImplementation(async (url, options) => url === badUrl ? success(200, "not json") : original(url, options));
      const out = await probe(target);
      expect(out.checks[badUrl === resource ? 1 : 2]).toMatchObject({ status: "fail", evidence: expect.stringContaining("malformed") });
    }
  });

  it("stops requests when the shared budget is exhausted", async () => {
    vi.useFakeTimers();
    try {
      vi.mocked(guardedFetch).mockImplementation(async () => { vi.advanceTimersByTime(10_000); return success(401, "", headers); });
      const result = await probe(target);
      expect(guardedFetch).toHaveBeenCalledTimes(1);
      expect(result.checks[1]?.status).toBe("not_checked");
      expect(result.checks[6]?.status).toBe("not_checked");
    } finally { vi.useRealTimers(); }
  });
});

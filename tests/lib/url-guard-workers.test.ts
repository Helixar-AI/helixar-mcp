// Unit tests for src/lib/url-guard.workers.ts — the Workers-runtime SSRF
// guard. DoH responses and the upstream fetch are stubbed via a single
// global fetch mock so the suite runs offline and deterministically.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { guardedFetch } from "../../src/lib/url-guard.workers.js";

// Build a minimal DoH JSON response for a single A or AAAA query.
function dohResponse(
  family: 4 | 6,
  addresses: string[],
  status = 0,
): Response {
  const type = family === 4 ? 1 : 28;
  return new Response(
    JSON.stringify({
      Status: status,
      Answer: addresses.map((address) => ({
        name: "example.com",
        type,
        TTL: 300,
        data: address,
      })),
    }),
    { status: 200, headers: { "content-type": "application/dns-json" } },
  );
}

// Build a fetch Response with a real ReadableStream body (the Workers guard
// uses getReader() which requires a real WHATWG stream).
function streamResponse(
  status: number,
  bodyText: string,
  headers: Record<string, string> = {},
): Response {
  return new Response(bodyText, { status, headers });
}

// Programmable fetch mock: a queue of (matcher → response) entries.
type FetchHandler = (url: string) => Response | Promise<Response> | null;
const handlers: FetchHandler[] = [];

function onFetch(handler: FetchHandler): void {
  handlers.push(handler);
}

beforeEach(() => {
  handlers.length = 0;
  vi.stubGlobal("fetch", async (input: string | Request, _init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.url;
    for (const h of handlers) {
      const out = await h(url);
      if (out) return out;
    }
    throw new Error(`no fetch handler matched: ${url}`);
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("guardedFetch (workers) — scheme + URL validation", () => {
  it("rejects non-https schemes", async () => {
    const r = await guardedFetch("http://example.com/manifest.json");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("insecure_scheme: http");
  });

  it("rejects file:// URLs", async () => {
    const r = await guardedFetch("file:///etc/passwd");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("insecure_scheme: file");
  });

  it("rejects malformed URLs", async () => {
    const r = await guardedFetch("not a url");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("invalid_url");
  });
});

describe("guardedFetch (workers) — DoH-based SSRF protection", () => {
  it("rejects when ANY resolved address is private (rebinding pair)", async () => {
    onFetch((url) => {
      if (url.includes("type=1")) return dohResponse(4, ["1.2.3.4", "127.0.0.1"]);
      if (url.includes("type=28")) return dohResponse(6, []);
      return null;
    });
    const r = await guardedFetch("https://attacker.example/manifest.json");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("blocked_address: private/reserved range");
  });

  it("rejects when AAAA-only response is private (loopback ::1)", async () => {
    onFetch((url) => {
      if (url.includes("type=1")) return dohResponse(4, []);
      if (url.includes("type=28")) return dohResponse(6, ["::1"]);
      return null;
    });
    const r = await guardedFetch("https://attacker.example/manifest.json");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("blocked_address: private/reserved range");
  });

  it("rejects IPv4-mapped IPv6 to a private IPv4 (::ffff:127.0.0.1)", async () => {
    onFetch((url) => {
      if (url.includes("type=1")) return dohResponse(4, []);
      if (url.includes("type=28")) return dohResponse(6, ["::ffff:127.0.0.1"]);
      return null;
    });
    const r = await guardedFetch("https://attacker.example/manifest.json");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("blocked_address: private/reserved range");
  });

  it("rejects 169.254.169.254 (cloud metadata)", async () => {
    onFetch((url) => {
      if (url.includes("type=1")) return dohResponse(4, ["169.254.169.254"]);
      if (url.includes("type=28")) return dohResponse(6, []);
      return null;
    });
    const r = await guardedFetch("https://attacker.example/");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("blocked_address: private/reserved range");
  });

  it("returns dns_lookup_failed when DoH yields no answers", async () => {
    onFetch((url) => {
      if (url.includes("dns-query")) return dohResponse(4, [], 3); // NXDOMAIN
      return null;
    });
    const r = await guardedFetch("https://nope.example/");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/dns_lookup_failed/);
  });
});

describe("guardedFetch (workers) — happy path + caps", () => {
  it("returns the body text on success", async () => {
    onFetch((url) => {
      if (url.includes("dns-query")) {
        return url.includes("type=1")
          ? dohResponse(4, ["93.184.216.34"])
          : dohResponse(6, []);
      }
      return streamResponse(200, '{"hello":"world"}');
    });
    const r = await guardedFetch("https://example.com/manifest.json");
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.text).toBe('{"hello":"world"}');
  });

  it("enforces the byte cap and returns response_too_large", async () => {
    const big = "x".repeat(2048);
    onFetch((url) => {
      if (url.includes("dns-query")) {
        return url.includes("type=1") ? dohResponse(4, ["93.184.216.34"]) : dohResponse(6, []);
      }
      return streamResponse(200, big);
    });
    const r = await guardedFetch("https://example.com/big", { maxBytes: 1024 });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("response_too_large");
  });

  it("re-validates redirects (Location to private IP host is rejected)", async () => {
    let phase: "first" | "redirected" = "first";
    onFetch((url) => {
      if (url.includes("dns-query")) {
        if (phase === "first") {
          return url.includes("type=1") ? dohResponse(4, ["93.184.216.34"]) : dohResponse(6, []);
        }
        // Second resolution (after redirect) returns a private IP.
        return url.includes("type=1") ? dohResponse(4, ["10.0.0.1"]) : dohResponse(6, []);
      }
      if (phase === "first") {
        phase = "redirected";
        return streamResponse(302, "", { location: "https://internal.example/secrets" });
      }
      return streamResponse(200, "secrets");
    });
    const r = await guardedFetch("https://example.com/start");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("blocked_address: private/reserved range");
  });

  it("rejects non-2xx upstream responses", async () => {
    onFetch((url) => {
      if (url.includes("dns-query")) {
        return url.includes("type=1") ? dohResponse(4, ["93.184.216.34"]) : dohResponse(6, []);
      }
      return streamResponse(500, "boom");
    });
    const r = await guardedFetch("https://example.com/bad");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("fetch returned 500");
  });
});

describe("guardedFetch auth probe options (Workers)", () => {
  it("sends only permitted OPTIONS headers and filters response headers", async () => {
    const fetchMock = vi.fn(async (input: string | Request, _init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.url;
      if (url.includes("dns-query")) return dohResponse(url.includes("type=28") ? 6 : 4, url.includes("type=28") ? [] : ["93.184.216.34"]);
      return streamResponse(401, "denied", { "www-authenticate": "Bearer test", "content-type": "text/plain", "set-cookie": "secret=1" });
    });
    vi.stubGlobal("fetch", fetchMock);
    const options = { method: "OPTIONS" as const, requestHeaders: { origin: "https://evil.example", accessControlRequestMethod: "POST" as const, authorization: "secret" }, acceptStatus: [401] };
    expect(await guardedFetch("https://example.com/", options)).toEqual({ ok: true, status: 401, text: "denied", headers: { "www-authenticate": "Bearer test", "content-type": "text/plain" } });
    const upstream = fetchMock.mock.calls.find(([url]) => url === "https://example.com/");
    expect(upstream?.[1]).toMatchObject({ method: "OPTIONS", headers: { origin: "https://evil.example", "access-control-request-method": "POST" } });
    expect(Object.keys(upstream?.[1]?.headers ?? {})).toHaveLength(2);
  });

  it("returns redirects without following them", async () => {
    onFetch((url) => url.includes("type=1") ? dohResponse(4, ["93.184.216.34"]) : null);
    onFetch((url) => url.includes("type=28") ? dohResponse(6, []) : null);
    onFetch((url) => url === "https://example.com/" ? streamResponse(302, "ignored", { location: "https://other.example/", "access-control-allow-origin": "*" }) : null);
    expect(await guardedFetch("https://example.com/", { followRedirects: false })).toEqual({ ok: true, status: 302, text: "", headers: { "access-control-allow-origin": "*", "content-type": "text/plain;charset=UTF-8" } });
  });

  it("keeps the deadline active while reading the response body", async () => {
    vi.stubGlobal("fetch", vi.fn(async (input: string | Request, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.url;
      if (url.includes("dns-query")) return dohResponse(url.includes("type=28") ? 6 : 4, url.includes("type=28") ? [] : ["93.184.216.34"]);
      return new Response(new ReadableStream({ start(controller) {
        init!.signal!.addEventListener("abort", () => controller.error(new Error("aborted")), { once: true });
      } }));
    }));
    const result = await guardedFetch("https://example.com/", { timeoutMs: 1000, deadlineMs: Date.now() + 30 });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("timeout");
  });

  it("cancels ignored redirect and rejected response bodies", async () => {
    for (const status of [302, 403]) {
      const cancel = vi.fn();
      vi.stubGlobal("fetch", vi.fn(async (input: string | Request) => {
        const url = typeof input === "string" ? input : input.url;
        if (url.includes("dns-query")) return dohResponse(url.includes("type=28") ? 6 : 4, url.includes("type=28") ? [] : ["93.184.216.34"]);
        return new Response(new ReadableStream({ cancel }), { status });
      }));
      await guardedFetch("https://example.com/", { followRedirects: false });
      expect(cancel).toHaveBeenCalledOnce();
    }
  });

  it("does not begin DNS after the deadline", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect(await guardedFetch("https://example.com/", { deadlineMs: Date.now() - 1 })).toEqual({ ok: false, reason: "deadline_exceeded" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

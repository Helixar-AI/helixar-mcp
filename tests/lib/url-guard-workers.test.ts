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

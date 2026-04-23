// Unit tests for src/lib/url-guard.ts — the SSRF mitigation layer behind
// inspectMcp's URL branch. Every network + DNS call is stubbed so the suite
// runs offline and deterministically.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The guard does `import * as dns from "node:dns/promises"` internally; we
// mock the module so every lookup goes through `mockLookup`.
const mockLookup = vi.fn();
vi.mock("node:dns/promises", () => ({
  lookup: (...args: unknown[]) => mockLookup(...args),
}));

import { guardedFetch, isPrivateAddress } from "../../src/lib/url-guard.js";

// Tiny helper — build a minimal fetch-compatible Response object. We only
// wire the fields guardedFetch actually reads: status, ok, body (as an
// async iterable), and (for redirects) headers.get("location").
function makeResponse(
  status: number,
  bodyChunks: Uint8Array[],
  headers: Record<string, string> = {},
): Response {
  const body = {
    async *[Symbol.asyncIterator]() {
      for (const chunk of bodyChunks) yield chunk;
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
    body,
  } as unknown as Response;
}

function enc(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

describe("isPrivateAddress", () => {
  it("rejects IPv4 loopback 127.0.0.0/8", () => {
    expect(isPrivateAddress("127.0.0.1", 4)).toBe(true);
    expect(isPrivateAddress("127.255.255.254", 4)).toBe(true);
  });

  it("rejects IPv4 10.0.0.0/8", () => {
    expect(isPrivateAddress("10.0.0.1", 4)).toBe(true);
    expect(isPrivateAddress("10.255.255.1", 4)).toBe(true);
  });

  it("rejects IPv4 172.16.0.0/12", () => {
    expect(isPrivateAddress("172.16.0.1", 4)).toBe(true);
    expect(isPrivateAddress("172.31.255.254", 4)).toBe(true);
    // Boundary — 172.15 and 172.32 are public.
    expect(isPrivateAddress("172.15.0.1", 4)).toBe(false);
    expect(isPrivateAddress("172.32.0.1", 4)).toBe(false);
  });

  it("rejects IPv4 192.168.0.0/16", () => {
    expect(isPrivateAddress("192.168.0.1", 4)).toBe(true);
    expect(isPrivateAddress("192.168.255.254", 4)).toBe(true);
  });

  it("rejects IPv4 169.254.0.0/16 (link-local + cloud metadata)", () => {
    expect(isPrivateAddress("169.254.169.254", 4)).toBe(true);
    expect(isPrivateAddress("169.254.1.1", 4)).toBe(true);
  });

  it("rejects IPv4 0.0.0.0/8", () => {
    expect(isPrivateAddress("0.0.0.0", 4)).toBe(true);
    expect(isPrivateAddress("0.1.2.3", 4)).toBe(true);
  });

  it("rejects IPv6 ::1 loopback", () => {
    expect(isPrivateAddress("::1", 6)).toBe(true);
  });

  it("rejects IPv6 fc00::/7 (ULA)", () => {
    expect(isPrivateAddress("fc00::1", 6)).toBe(true);
    expect(isPrivateAddress("fd12:3456:789a::1", 6)).toBe(true);
  });

  it("rejects IPv6 fe80::/10 (link-local)", () => {
    expect(isPrivateAddress("fe80::1", 6)).toBe(true);
  });

  it("rejects IPv4-mapped IPv6 for blocked IPv4", () => {
    expect(isPrivateAddress("::ffff:127.0.0.1", 6)).toBe(true);
    expect(isPrivateAddress("::ffff:169.254.169.254", 6)).toBe(true);
    expect(isPrivateAddress("::ffff:7f00:1", 6)).toBe(true);
  });

  it("allows a public IPv4 (e.g. 93.184.216.34)", () => {
    expect(isPrivateAddress("93.184.216.34", 4)).toBe(false);
  });

  it("allows a public IPv6 (e.g. 2606:2800::1)", () => {
    expect(isPrivateAddress("2606:2800::1", 6)).toBe(false);
  });
});

describe("guardedFetch", () => {
  beforeEach(() => {
    mockLookup.mockReset();
    vi.unstubAllGlobals();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("rejects an unparseable URL", async () => {
    const res = await guardedFetch("not a url");
    expect(res).toEqual({ ok: false, reason: "invalid_url" });
  });

  it("rejects http:// with insecure_scheme", async () => {
    const res = await guardedFetch("http://example.com/m.json");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/insecure_scheme.*http/i);
  });

  it("rejects file:///etc/passwd with insecure_scheme", async () => {
    const res = await guardedFetch("file:///etc/passwd");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/insecure_scheme.*file/i);
  });

  it("rejects http://localhost via scheme (never reaches DNS)", async () => {
    const res = await guardedFetch("http://localhost/admin");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/insecure_scheme/i);
    expect(mockLookup).not.toHaveBeenCalled();
  });

  it("rejects https://127.0.0.1 via DNS (private range)", async () => {
    mockLookup.mockResolvedValueOnce([{ address: "127.0.0.1", family: 4 }]);
    const res = await guardedFetch("https://127.0.0.1/");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/blocked|private/i);
  });

  it("rejects https://[::1] via DNS (private range)", async () => {
    mockLookup.mockResolvedValueOnce([{ address: "::1", family: 6 }]);
    const res = await guardedFetch("https://[::1]/");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/blocked|private/i);
  });

  it("rejects https://example.com when DNS poisons to 169.254.169.254", async () => {
    mockLookup.mockResolvedValueOnce([{ address: "169.254.169.254", family: 4 }]);
    const res = await guardedFetch("https://example.com/");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/blocked|private/i);
  });

  it("rejects when any resolved address is private (mixed result)", async () => {
    mockLookup.mockResolvedValueOnce([
      { address: "93.184.216.34", family: 4 },
      { address: "127.0.0.1", family: 4 },
    ]);
    const res = await guardedFetch("https://example.com/");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/blocked|private/i);
  });

  it("enforces timeout via AbortController", async () => {
    mockLookup.mockResolvedValueOnce([{ address: "93.184.216.34", family: 4 }]);
    const fetchMock = vi.fn(
      (_url: string, init?: { signal?: AbortSignal }) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            const err = new Error("aborted");
            err.name = "AbortError";
            reject(err);
          });
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const res = await guardedFetch("https://example.com/", { timeoutMs: 20 });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/timeout/i);
  });

  it("enforces maxBytes and aborts the stream", async () => {
    mockLookup.mockResolvedValueOnce([{ address: "93.184.216.34", family: 4 }]);
    // 200 KB of payload, cap at 50 KB.
    const big = enc("A".repeat(200_000));
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => makeResponse(200, [big])),
    );
    const res = await guardedFetch("https://example.com/", { maxBytes: 50_000 });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("response_too_large");
  });

  it("follows up to 3 redirects through the same guard", async () => {
    // 3 hops → 200. Each hop resolves to a public IP.
    mockLookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(makeResponse(301, [], { Location: "https://b.example.com/2" }))
      .mockResolvedValueOnce(makeResponse(302, [], { Location: "https://c.example.com/3" }))
      .mockResolvedValueOnce(makeResponse(303, [], { Location: "https://d.example.com/4" }))
      .mockResolvedValueOnce(makeResponse(200, [enc("ok")]));
    vi.stubGlobal("fetch", fetchMock);
    const res = await guardedFetch("https://a.example.com/1");
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.text).toBe("ok");
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it("rejects on the 4th redirect hop", async () => {
    mockLookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(makeResponse(301, [], { Location: "https://b.example.com/2" }))
      .mockResolvedValueOnce(makeResponse(301, [], { Location: "https://c.example.com/3" }))
      .mockResolvedValueOnce(makeResponse(301, [], { Location: "https://d.example.com/4" }))
      .mockResolvedValueOnce(makeResponse(301, [], { Location: "https://e.example.com/5" }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await guardedFetch("https://a.example.com/1");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/redirect/i);
  });

  it("re-validates redirect target through the guard — rejects redirect to private IP", async () => {
    // First hop public; redirect target's DNS resolves to 127.0.0.1.
    mockLookup
      .mockResolvedValueOnce([{ address: "93.184.216.34", family: 4 }])
      .mockResolvedValueOnce([{ address: "127.0.0.1", family: 4 }]);
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(makeResponse(302, [], { Location: "https://internal.example.com/" }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await guardedFetch("https://a.example.com/");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/blocked|private/i);
  });

  it("rejects 3xx without a Location header", async () => {
    mockLookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    vi.stubGlobal("fetch", vi.fn(async () => makeResponse(302, [])));
    const res = await guardedFetch("https://a.example.com/");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/redirect|location/i);
  });

  it("happy path — valid HTTPS + public IP + small body returns text", async () => {
    mockLookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => makeResponse(200, [enc("hello world")])),
    );
    const res = await guardedFetch("https://example.com/m.json");
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.text).toBe("hello world");
  });

  it("passes redirect: manual to fetch", async () => {
    mockLookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    const fetchMock = vi.fn(async () => makeResponse(200, [enc("ok")]));
    vi.stubGlobal("fetch", fetchMock);
    await guardedFetch("https://example.com/");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const init = fetchMock.mock.calls[0]?.[1] as { redirect?: string } | undefined;
    expect(init?.redirect).toBe("manual");
  });
});

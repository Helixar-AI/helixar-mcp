// SSRF mitigation for caller-supplied URLs.
//
// guardedFetch() is the single entry point used by tools that accept a URL
// from the model / caller (today: inspectMcp). It enforces:
//
//   • HTTPS-only — http/file/ftp/ws/etc. are rejected up-front.
//   • DNS lookup with private-range rejection (loopback, RFC1918, link-local
//     incl. 169.254.169.254 cloud metadata, IPv6 ULA/link-local/::1, and
//     IPv4-mapped IPv6 for any blocked IPv4).
//   • DNS-rebinding protection — the IP returned by our validated lookup is
//     pinned for the actual TCP connect via a per-request undici Agent with a
//     custom `connect.lookup` hook. undici therefore never re-resolves the
//     hostname and cannot be steered to a private IP by a TTL=0 authoritative
//     resolver. TLS SNI / cert verification still use the hostname.
//   • redirect: "manual" — every 3xx is re-validated through the same guard;
//     max 3 redirect hops.
//   • AbortController-driven timeout (default 10 s).
//   • Streaming byte cap (default 512 KB) — exceeding the cap aborts the
//     stream and returns response_too_large rather than buffering forever.
//
// All rejections surface as { ok: false, reason: string } so callers can
// render a structured error without guessing the failure mode.

import { lookup } from "node:dns/promises";
import { Agent, type Dispatcher } from "undici";

export interface GuardedFetchOptions {
  maxBytes?: number;
  timeoutMs?: number;
}

export type GuardedFetchResult =
  | { ok: true; text: string }
  | { ok: false; reason: string };

const DEFAULT_MAX_BYTES = 512 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 3;

// ───────────────────────────────────────────────────────────────────────────
// IP classification
// ───────────────────────────────────────────────────────────────────────────

function ipv4ToInt(addr: string): number | null {
  const parts = addr.split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const raw of parts) {
    if (!/^\d{1,3}$/.test(raw)) return null;
    const n = Number(raw);
    if (n < 0 || n > 255) return null;
    out = (out * 256) + n;
  }
  return out;
}

function isBlockedIPv4(addr: string): boolean {
  const int = ipv4ToInt(addr);
  if (int === null) return false;
  // Note: bitwise operators in JS coerce operands to 32-bit signed integers,
  // so we apply `>>> 0` to both sides to compare as unsigned.
  const masked = (mask: number) => (int & mask) >>> 0;
  // 0.0.0.0/8
  if (masked(0xff000000) === 0x00000000) return true;
  // 10.0.0.0/8
  if (masked(0xff000000) === 0x0a000000) return true;
  // 127.0.0.0/8 (loopback)
  if (masked(0xff000000) === 0x7f000000) return true;
  // 169.254.0.0/16 (link-local incl. 169.254.169.254 cloud metadata)
  if (masked(0xffff0000) === 0xa9fe0000) return true;
  // 172.16.0.0/12
  if (masked(0xfff00000) === 0xac100000) return true;
  // 192.168.0.0/16
  if (masked(0xffff0000) === 0xc0a80000) return true;
  return false;
}

function normaliseIPv6(addr: string): string {
  // Strip any zone id (e.g. fe80::1%eth0) and lowercase for prefix matching.
  const noZone = addr.split("%")[0] ?? addr;
  return noZone.toLowerCase();
}

function isBlockedIPv6(addr: string): boolean {
  const norm = normaliseIPv6(addr);
  // Loopback ::1 (in any equivalent form).
  if (norm === "::1" || norm === "0:0:0:0:0:0:0:1") return true;
  // Unspecified ::
  if (norm === "::" || norm === "0:0:0:0:0:0:0:0") return true;
  // fc00::/7 — unique local addresses (fc00::..fdff::)
  if (/^f[cd][0-9a-f]{0,2}:/i.test(norm)) return true;
  // fe80::/10 — link-local (fe80..febf)
  if (/^fe[89ab][0-9a-f]{0,1}:/i.test(norm)) return true;
  // IPv4-mapped IPv6 ::ffff:a.b.c.d or ::ffff:xxxx:yyyy
  const mapped4 = norm.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (mapped4 && mapped4[1]) {
    return isBlockedIPv4(mapped4[1]);
  }
  const mappedHex = norm.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mappedHex && mappedHex[1] && mappedHex[2]) {
    const hi = parseInt(mappedHex[1], 16);
    const lo = parseInt(mappedHex[2], 16);
    const dotted = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
    return isBlockedIPv4(dotted);
  }
  return false;
}

export function isPrivateAddress(addr: string, family: number): boolean {
  if (family === 4) return isBlockedIPv4(addr);
  if (family === 6) return isBlockedIPv6(addr);
  return false;
}

// ───────────────────────────────────────────────────────────────────────────
// DNS + pinned-dispatcher construction.
// ───────────────────────────────────────────────────────────────────────────

interface SafeAddress {
  address: string;
  family: 4 | 6;
}

async function resolveAndValidate(
  hostname: string,
): Promise<{ ok: true; safe: SafeAddress } | { ok: false; reason: string }> {
  // Strip the surrounding brackets that URL parser keeps on IPv6 literals.
  const host = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  let results: Array<{ address: string; family: number }>;
  try {
    results = await lookup(host, { all: true });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: `dns_lookup_failed: ${msg}` };
  }
  if (results.length === 0) {
    return { ok: false, reason: "dns_lookup_failed: no addresses" };
  }
  // Reject if ANY returned address is private — a public+private pair is the
  // classic rebinding trick.
  for (const r of results) {
    if (isPrivateAddress(r.address, r.family)) {
      return { ok: false, reason: "blocked_address: private/reserved range" };
    }
  }
  const chosen = results[0];
  if (!chosen || (chosen.family !== 4 && chosen.family !== 6)) {
    return { ok: false, reason: "dns_lookup_failed: unexpected family" };
  }
  return {
    ok: true,
    safe: { address: chosen.address, family: chosen.family as 4 | 6 },
  };
}

/**
 * Build an undici Agent whose `connect.lookup` hook ALWAYS returns the
 * pre-validated IP. This closes the DNS-TOCTOU / rebinding gap — undici
 * cannot re-resolve the hostname and be steered to a private IP between our
 * check and the actual connect(). TLS SNI / cert verification still use the
 * hostname, so HTTPS to any public host continues to work unchanged.
 *
 * Exported for unit-testing in isolation.
 */
export function _createPinnedDispatcher(safe: SafeAddress): Dispatcher {
  return new Agent({
    connect: {
      lookup: (
        _hostname: string,
        _options: unknown,
        cb: (err: Error | null, address: string, family: number) => void,
      ) => {
        cb(null, safe.address, safe.family);
      },
    },
  });
}

// ───────────────────────────────────────────────────────────────────────────
// guardedFetch — main entry
// ───────────────────────────────────────────────────────────────────────────

export async function guardedFetch(
  url: string,
  options: GuardedFetchOptions = {},
): Promise<GuardedFetchResult> {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  return fetchWithGuard(url, maxBytes, timeoutMs, 0);
}

async function fetchWithGuard(
  url: string,
  maxBytes: number,
  timeoutMs: number,
  hop: number,
): Promise<GuardedFetchResult> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, reason: "invalid_url" };
  }

  if (parsed.protocol !== "https:") {
    // Strip trailing ':' from protocol for cleaner reason string.
    const scheme = parsed.protocol.replace(/:$/, "");
    return { ok: false, reason: `insecure_scheme: ${scheme}` };
  }

  const resolved = await resolveAndValidate(parsed.hostname);
  if (!resolved.ok) return resolved;

  const dispatcher = _createPinnedDispatcher(resolved.safe);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    // `dispatcher` is a Node-fetch extension (from undici) not covered by the
    // built-in lib.dom types, so we cast to add the field.
    response = await fetch(url, {
      redirect: "manual",
      signal: controller.signal,
      dispatcher,
    } as RequestInit & { dispatcher: Dispatcher });
  } catch (err) {
    clearTimeout(timer);
    if (controller.signal.aborted) {
      return { ok: false, reason: `timeout after ${timeoutMs}ms` };
    }
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: `fetch failed: ${msg}` };
  }

  // Handle redirects manually so we can re-run the full guard on Location.
  if (response.status >= 300 && response.status < 400) {
    clearTimeout(timer);
    const location = response.headers.get("location");
    if (!location) {
      return { ok: false, reason: `redirect ${response.status} without Location header` };
    }
    if (hop >= MAX_REDIRECTS) {
      return { ok: false, reason: `too many redirects (> ${MAX_REDIRECTS})` };
    }
    // Resolve relative Location against the current URL.
    let nextUrl: string;
    try {
      nextUrl = new URL(location, url).toString();
    } catch {
      return { ok: false, reason: "redirect Location is not a valid URL" };
    }
    return fetchWithGuard(nextUrl, maxBytes, timeoutMs, hop + 1);
  }

  if (!response.ok) {
    clearTimeout(timer);
    return { ok: false, reason: `fetch returned ${response.status}` };
  }

  // Stream the body and enforce maxBytes. We prefer the async-iterator path
  // (Node 20's undici exposes it on response.body) because it lets us abort
  // as soon as the cap is breached rather than buffering the full payload.
  try {
    const body = response.body as AsyncIterable<Uint8Array> | null | undefined;
    if (!body || typeof (body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator] !== "function") {
      // Fallback: read as text, but still enforce the cap post-hoc.
      const text = await response.text();
      if (Buffer.byteLength(text, "utf8") > maxBytes) {
        return { ok: false, reason: "response_too_large" };
      }
      return { ok: true, text };
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    for await (const chunk of body) {
      total += chunk.byteLength;
      if (total > maxBytes) {
        controller.abort();
        return { ok: false, reason: "response_too_large" };
      }
      chunks.push(chunk);
    }
    const buf = Buffer.concat(chunks.map((c) => Buffer.from(c)));
    return { ok: true, text: buf.toString("utf8") };
  } catch (err) {
    if (controller.signal.aborted) {
      return { ok: false, reason: `timeout after ${timeoutMs}ms` };
    }
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: `read failed: ${msg}` };
  } finally {
    clearTimeout(timer);
  }
}

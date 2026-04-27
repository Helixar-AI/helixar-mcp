// SSRF mitigation for caller-supplied URLs (Node runtime).
//
// guardedFetch() is the single entry point used by tools that accept a URL
// from the model / caller (today: inspectMcp). It enforces:
//
//   • HTTPS-only — http/file/ftp/ws/etc. are rejected up-front.
//   • DNS lookup with private-range rejection (loopback, RFC1918, link-local
//     incl. 169.254.169.254 cloud metadata, IPv6 ULA/link-local/::1, and
//     IPv4-mapped IPv6 for any blocked IPv4).
//   • Bounded DNS lookup — the dns.lookup() call is raced against the request
//     timeout so a slow resolver cannot stall the fetch indefinitely (the
//     AbortController that guards the fetch itself isn't armed yet at this
//     point, so without a race a hostile resolver could hold the call open).
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
//
// IP classification (expandIPv6, isPrivateAddress, etc.) lives in
// ./url-classify.ts so it can be reused by the Workers runtime guard at
// ./url-guard.workers.ts.

import { lookup } from "node:dns/promises";
import { Agent, type Dispatcher } from "undici";
import {
  DEFAULT_MAX_BYTES,
  DEFAULT_TIMEOUT_MS,
  isPrivateAddress,
  MAX_REDIRECTS,
  type GuardedFetchOptions,
  type GuardedFetchResult,
} from "./url-classify.js";

// Re-exports preserve the import surface for existing callers and tests.
export {
  expandIPv6,
  isPrivateAddress,
  type GuardedFetchOptions,
  type GuardedFetchResult,
} from "./url-classify.js";

// ───────────────────────────────────────────────────────────────────────────
// DNS + pinned-dispatcher construction.
// ───────────────────────────────────────────────────────────────────────────

interface SafeAddress {
  address: string;
  family: 4 | 6;
}

async function resolveAndValidate(
  hostname: string,
  timeoutMs: number,
): Promise<{ ok: true; safe: SafeAddress } | { ok: false; reason: string }> {
  // Strip the surrounding brackets that URL parser keeps on IPv6 literals.
  const host = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  // Race the lookup against the caller's timeout so a slow or adversarial
  // resolver cannot stall guardedFetch indefinitely — the AbortController
  // below is only armed AFTER this call returns.
  let timer: ReturnType<typeof setTimeout> | undefined;
  let results: Array<{ address: string; family: number }>;
  try {
    const lookupPromise = lookup(host, { all: true });
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("dns_timeout")), timeoutMs);
    });
    results = await Promise.race([lookupPromise, timeoutPromise]);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg === "dns_timeout") {
      return { ok: false, reason: `dns_timeout after ${timeoutMs}ms` };
    }
    return { ok: false, reason: `dns_lookup_failed: ${msg}` };
  } finally {
    if (timer) clearTimeout(timer);
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

  const resolved = await resolveAndValidate(parsed.hostname, timeoutMs);
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
      // Node 20+ always provides a streamable body on fetch Responses. A
      // missing body here indicates either a mocked response (tests should
      // always supply one) or a very unusual transport anomaly — reject
      // rather than fall back to an unsigned response.text() which would
      // bypass the size cap and the abort signal (a 100 MB body would be
      // fully buffered before we could check the cap post-hoc).
      return { ok: false, reason: "empty_body" };
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

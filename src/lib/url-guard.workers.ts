// SSRF mitigation for caller-supplied URLs (Cloudflare Workers runtime).
//
// Mirrors the contract of ./url-guard.ts (Node) but uses Cloudflare DoH for
// DNS resolution and the platform `fetch()` for the actual request, since the
// undici-based connect-time DNS pinning used by the Node guard has no Workers
// equivalent without a hand-rolled TLS+HTTP client over `cloudflare:sockets`.
//
// What this guard DOES enforce:
//   • HTTPS-only (http/file/ftp/ws/etc. rejected up-front).
//   • DoH (1.1.1.1) lookup for A + AAAA. ALL returned addresses are checked;
//     if ANY address is private (loopback, RFC1918, link-local incl. cloud
//     metadata, IPv6 ULA / link-local / ::1, IPv4-mapped IPv6 for blocked
//     IPv4), the request is rejected. This blocks the classic "public+private
//     pair" rebinding payload and any straightforward attempt to address an
//     internal range by hostname.
//   • Bounded DoH lookup (raced against the request timeout).
//   • redirect: "manual" — every 3xx is re-validated through the same guard;
//     max 3 redirect hops.
//   • AbortController-driven timeout (default 10 s).
//   • Streaming byte cap (default 512 KB) — exceeding the cap aborts the
//     stream and returns response_too_large rather than buffering forever.
//
// What this guard DOES NOT enforce (yet):
//   • Connect-time IP pinning. The Workers runtime resolves DNS itself when
//     issuing the fetch; an attacker controlling a domain's authoritative
//     resolver could in principle return a public IP for our DoH lookup and a
//     private IP for the Workers lookup that follows (DNS-rebinding TOCTOU).
//     The window is narrower than on a standard Node host because Workers'
//     resolver is Cloudflare's globally-cached infrastructure rather than a
//     local stub, but the gap is real. Tracked in repo issue
//     Helixar-AI/helixar-mcp#13.
//
// All rejections surface as { ok: false, reason: string } — same shape as the
// Node guard so callers (inspect-mcp.ts) need no runtime-aware branches.

import {
  DEFAULT_MAX_BYTES,
  DEFAULT_TIMEOUT_MS,
  isPrivateAddress,
  MAX_REDIRECTS,
  type GuardedFetchOptions,
  type GuardedFetchResult,
} from "./url-classify.js";

export {
  type GuardedFetchOptions,
  type GuardedFetchResult,
} from "./url-classify.js";

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

// DNS record types we resolve. 1 = A (IPv4), 28 = AAAA (IPv6).
const DOH_TYPES = [
  { type: 1, family: 4 as const },
  { type: 28, family: 6 as const },
];

interface DohJsonAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DohJsonResponse {
  Status: number;
  Answer?: DohJsonAnswer[];
}

interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

async function dohLookup(
  hostname: string,
  timeoutMs: number,
): Promise<{ ok: true; addresses: ResolvedAddress[] } | { ok: false; reason: string }> {
  const host = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const queries = DOH_TYPES.map(async ({ type, family }) => {
      const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(host)}&type=${type}`;
      const res = await fetch(url, {
        headers: { accept: "application/dns-json" },
        signal: controller.signal,
      });
      if (!res.ok) return [] as ResolvedAddress[];
      const json = (await res.json()) as DohJsonResponse;
      // Status 0 = NOERROR; anything else (NXDOMAIN, SERVFAIL) yields no
      // addresses for that family — that's fine, the other family may answer.
      if (json.Status !== 0 || !json.Answer) return [] as ResolvedAddress[];
      return json.Answer
        // Only A/AAAA — ignore CNAME chain entries (DoH unrolls them, but
        // belt-and-braces in case Cloudflare's responder ever changes shape).
        .filter((a) => a.type === type)
        .map((a) => ({ address: a.data, family }));
    });

    const perFamily = await Promise.all(queries);
    const addresses = perFamily.flat();
    if (addresses.length === 0) {
      return { ok: false, reason: "dns_lookup_failed: no addresses" };
    }
    return { ok: true, addresses };
  } catch (err) {
    if (controller.signal.aborted) {
      return { ok: false, reason: `dns_timeout after ${timeoutMs}ms` };
    }
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: `dns_lookup_failed: ${msg}` };
  } finally {
    clearTimeout(timer);
  }
}

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
    const scheme = parsed.protocol.replace(/:$/, "");
    return { ok: false, reason: `insecure_scheme: ${scheme}` };
  }

  const resolved = await dohLookup(parsed.hostname, timeoutMs);
  if (!resolved.ok) return resolved;

  // Reject if ANY returned address is private — public+private pair is the
  // classic rebinding payload.
  for (const a of resolved.addresses) {
    if (isPrivateAddress(a.address, a.family)) {
      return { ok: false, reason: "blocked_address: private/reserved range" };
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(url, {
      redirect: "manual",
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    if (controller.signal.aborted) {
      return { ok: false, reason: `timeout after ${timeoutMs}ms` };
    }
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: `fetch failed: ${msg}` };
  }

  if (response.status >= 300 && response.status < 400) {
    clearTimeout(timer);
    const location = response.headers.get("location");
    if (!location) {
      return { ok: false, reason: `redirect ${response.status} without Location header` };
    }
    if (hop >= MAX_REDIRECTS) {
      return { ok: false, reason: `too many redirects (> ${MAX_REDIRECTS})` };
    }
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

  try {
    const body = response.body;
    if (!body) return { ok: false, reason: "empty_body" };
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        controller.abort();
        try { await reader.cancel(); } catch { /* best-effort */ }
        return { ok: false, reason: "response_too_large" };
      }
      chunks.push(value);
    }
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      merged.set(c, offset);
      offset += c.byteLength;
    }
    return { ok: true, text: new TextDecoder().decode(merged) };
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

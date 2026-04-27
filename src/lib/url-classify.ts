// Pure IP classification — runtime-agnostic. Used by both the Node SSRF guard
// (src/lib/url-guard.ts) and the Workers SSRF guard
// (src/lib/url-guard.workers.ts). No `node:*` imports, no DOM, no globals
// beyond ES2022.

// ───────────────────────────────────────────────────────────────────────────
// IPv6 canonicalization — expand to 8 numeric groups before classifying.
// ───────────────────────────────────────────────────────────────────────────

/**
 * Expand any syntactically valid IPv6 address into 8 numeric 16-bit groups.
 *
 * Handles: `::`, zero compression anywhere (`0::1`, `0:0::1`, `::0:1`…),
 * fully-expanded `0000:0000:0000:0000:0000:0000:0000:0001`, bracketed
 * literals `[::1]`, embedded IPv4 (`::ffff:127.0.0.1`), and zone ids
 * (`fe80::1%eth0`). Returns null for anything unparseable.
 */
export function expandIPv6(addrIn: string): number[] | null {
  let addr = addrIn;
  const pct = addr.indexOf("%");
  if (pct >= 0) addr = addr.slice(0, pct);
  if (addr.startsWith("[") && addr.endsWith("]")) addr = addr.slice(1, -1);
  const v4Match = addr.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (v4Match && v4Match[1] !== undefined && v4Match[2] !== undefined) {
    const parts = v4Match[2].split(".").map((n) => Number(n));
    if (
      parts.length !== 4 ||
      parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)
    ) {
      return null;
    }
    const hi = ((parts[0] ?? 0) << 8) | (parts[1] ?? 0);
    const lo = ((parts[2] ?? 0) << 8) | (parts[3] ?? 0);
    addr = v4Match[1] + hi.toString(16) + ":" + lo.toString(16);
  }
  const dcCount = (addr.match(/::/g) ?? []).length;
  if (dcCount > 1) return null;
  let headStr: string;
  let tailStr: string | undefined;
  if (dcCount === 1) {
    const [h, t] = addr.split("::");
    headStr = h ?? "";
    tailStr = t ?? "";
  } else {
    headStr = addr;
    tailStr = undefined;
  }
  const headGroups = headStr === "" ? [] : headStr.split(":");
  const tailGroups =
    tailStr === undefined ? [] : tailStr === "" ? [] : tailStr.split(":");
  if (tailStr === undefined && headGroups.length !== 8) return null;
  const fillCount = 8 - headGroups.length - tailGroups.length;
  if (fillCount < 0) return null;
  if (tailStr !== undefined && fillCount < 1) return null;
  const rawGroups = [
    ...headGroups,
    ...Array(fillCount).fill("0"),
    ...tailGroups,
  ];
  if (rawGroups.length !== 8) return null;
  const groups: number[] = [];
  for (const g of rawGroups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    groups.push(parseInt(g, 16));
  }
  return groups;
}

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
  // Bitwise operators in JS coerce to 32-bit signed; `>>> 0` makes it unsigned.
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

function isBlockedIPv6(addr: string): boolean {
  const groups = expandIPv6(addr);
  if (!groups) return false;
  const g0 = groups[0] ?? 0;
  // Loopback ::1
  if (
    groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 &&
    groups[4] === 0 && groups[5] === 0 && groups[6] === 0 && groups[7] === 1
  ) {
    return true;
  }
  // Unspecified ::
  if (groups.every((g) => g === 0)) return true;
  // fc00::/7 — ULA
  if ((g0 & 0xfe00) === 0xfc00) return true;
  // fe80::/10 — link-local
  if ((g0 & 0xffc0) === 0xfe80) return true;
  // ::ffff:a.b.c.d — IPv4-mapped IPv6
  if (
    groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 &&
    groups[4] === 0 && groups[5] === 0xffff
  ) {
    const g6 = groups[6] ?? 0;
    const g7 = groups[7] ?? 0;
    const dotted = `${(g6 >> 8) & 0xff}.${g6 & 0xff}.${(g7 >> 8) & 0xff}.${g7 & 0xff}`;
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
// Shared SSRF-guard constants & types
// ───────────────────────────────────────────────────────────────────────────

export const DEFAULT_MAX_BYTES = 512 * 1024;
export const DEFAULT_TIMEOUT_MS = 10_000;
export const MAX_REDIRECTS = 3;

export interface GuardedFetchOptions {
  maxBytes?: number;
  timeoutMs?: number;
}

export type GuardedFetchResult =
  | { ok: true; text: string }
  | { ok: false; reason: string };

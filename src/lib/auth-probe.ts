import { guardedFetch, type GuardedFetchOptions, type GuardedFetchResult } from "#url-guard";
import { escapeEvidence } from "./poisoning.js";
import { refsFor, type RuleRefs } from "./taxonomy.js";

export const MAX_REQUESTS = 8;
export const PER_REQUEST_TIMEOUT_MS = 2_500;
export const TOTAL_BUDGET_MS = 10_000;
export const MAX_BODY_BYTES = 65_536;
const authentication = "authentication" as const;
const source = "MCP Authorization: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization";
export const AUTH_CHECKS = ([
  {
    id: "A-001", title: "Protected resource challenge", severity: "high", category: authentication,
    description: "The server responds with 401 and advertises protected-resource metadata.",
    remediation: "For a protected MCP endpoint, return a Bearer challenge that advertises its metadata URL.",
  },
  {
    id: "A-002", title: "Protected resource metadata", severity: "high", category: authentication,
    description: "The resource metadata identifies the target resource and advertises an authorization server.",
    remediation: "Publish RFC 9728 metadata with the canonical resource URL and authorization servers.",
  },
  {
    id: "A-003", title: "Authorization server metadata", severity: "high", category: authentication,
    description: "Authorization-server metadata declares the issuer, authorization endpoint, and token endpoint.",
    remediation: "Publish RFC 8414 or OpenID discovery metadata with the required endpoint fields.",
  },
  {
    id: "A-004", title: "PKCE S256 advertised", severity: "high", category: authentication,
    description: "The authorization server advertises PKCE with the S256 code challenge method.",
    remediation: "Support S256 and advertise it in code_challenge_methods_supported.",
  },
  {
    id: "A-005", title: "Resource indicators advertised", severity: "medium", category: authentication,
    description: "The authorization server advertises support for the resource parameter.",
    remediation: "Support RFC 8707 resource indicators and declare support in server metadata.",
  },
  {
    id: "A-006", title: "Dynamic registration advertised", severity: "medium", category: authentication,
    description: "An advertised registration endpoint warrants review of client registration controls.",
    remediation: "Review who can register OAuth clients and how the authorization server restricts registration.",
  },
  {
    id: "A-007", title: "CORS preflight origin policy", severity: "high", category: "authorization",
    description: "The response indicates whether a preflight permits an unrelated origin.",
    remediation: "Allow only intended browser origins and validate Origin on MCP requests.",
  },
  {
    id: "A-008", title: "HTTPS metadata discovery", severity: "high", category: authentication,
    description: "The endpoint and metadata discovery URLs use HTTPS.",
    remediation: "Advertise HTTPS URLs for protected-resource and authorization-server metadata.",
  },
] as const).map((entry) => ({ ...entry, mode: "quick" as const, source }));

export type AuthCheckId = (typeof AUTH_CHECKS)[number]["id"];
export type AuthStatus = "pass" | "fail" | "warn" | "inferred" | "not_checked";
export interface AuthCheck {
  id: AuthCheckId;
  status: AuthStatus;
  evidence: string;
  refs: RuleRefs;
  origin_validation?: "inferred";
}
export interface AuthProbeResult {
  authorization_server?: string;
  checks: AuthCheck[];
}

function check(id: AuthCheckId, status: AuthStatus, evidence: string): AuthCheck {
  return {
    id, status, evidence: escapeEvidence(evidence), refs: refsFor(id),
    ...(id === "A-007" && status !== "not_checked" ? { origin_validation: "inferred" } : {}),
  };
}
type Request = (url: string, options?: GuardedFetchOptions) => Promise<GuardedFetchResult | undefined>;
type SetCheck = (id: AuthCheckId, status: AuthStatus, evidence: string) => void;
type Metadata = Record<string, unknown>;

function jsonObject(text: string): Metadata | undefined {
  try {
    const value: unknown = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value) ? value as Metadata : undefined;
  } catch { return undefined; }
}
function parsedUrl(value: string, allowQuery = false): URL | undefined {
  try {
    const url = new URL(value);
    return url.username || url.password || url.hash || (!allowQuery && url.search) ? undefined : url;
  } catch { return undefined; }
}

// Split only at commas outside quoted strings. A quoted error_description can
// contain text that looks like a parameter, but is never an auth-param itself.
function metadataParameter(header: string): string | undefined {
  const parts: string[] = [];
  let start = 0, quoted = false, escaped = false;
  for (let i = 0; i < header.length; i++) {
    const char = header[i];
    if (escaped) { escaped = false; continue; }
    if (quoted && char === "\\") { escaped = true; continue; }
    if (char === '"') quoted = !quoted;
    else if (char === "," && !quoted) { parts.push(header.slice(start, i)); start = i + 1; }
  }
  parts.push(header.slice(start));
  for (const part of parts) {
    const match = /^\s*(?:[!#$%&'*+.^_`|~0-9A-Za-z-]+\s+)?resource_metadata\s*=\s*(?:"([^"\\]*(?:\\.[^"\\]*)*)"|([!#$%&'*+.^_`|~0-9A-Za-z-]+))\s*$/i.exec(part);
    if (match) return match[1]?.replace(/\\(.)/g, "$1") ?? match[2];
  }
  return undefined;
}

async function fetchMetadata(candidates: string[], request: Request): Promise<{ fetched: boolean; value?: Metadata }> {
  for (const candidate of candidates) {
    const response = await request(candidate);
    if (response?.ok && response.status >= 200 && response.status < 300) {
      return { fetched: true, value: jsonObject(response.text) };
    }
  }
  return { fetched: false };
}

async function discoverResource(target: URL, advertised: string | undefined, request: Request, set: SetCheck): Promise<{ issuer?: string; insecure: boolean }> {
  let candidates: string[];
  if (advertised !== undefined) {
    const candidate = parsedUrl(advertised, true);
    if (!candidate) {
      set("A-002", "not_checked", "Advertised protected-resource metadata URL is invalid.");
      return { insecure: false };
    }
    if (candidate.protocol !== "https:") {
      set("A-002", "not_checked", "Advertised protected-resource metadata URL is not HTTPS.");
      return { insecure: true };
    }
    if (candidate.origin !== target.origin) {
      set("A-002", "not_checked", "Advertised protected-resource metadata URL is outside the target origin.");
      return { insecure: false };
    }
    candidates = [candidate.href];
  } else {
    const path = target.pathname === "/" ? "" : target.pathname.replace(/\/$/, "");
    candidates = [...new Set([`${target.origin}/.well-known/oauth-protected-resource${path}`, `${target.origin}/.well-known/oauth-protected-resource`])];
  }
  const metadata = await fetchMetadata(candidates, request);
  if (!metadata.fetched) return { insecure: false };
  if (!metadata.value) {
    set("A-002", "fail", "Protected-resource metadata is malformed JSON or not an object.");
    return { insecure: false };
  }
  const servers = metadata.value.authorization_servers;
  const valid = metadata.value.resource === target.origin + target.pathname && Array.isArray(servers) && typeof servers[0] === "string" && servers[0].length > 0;
  set("A-002", valid ? "pass" : "fail", valid ? "Protected-resource metadata contains the expected resource and an authorization server." : "Protected-resource metadata is missing the expected resource or an authorization server.");
  return { ...(valid ? { issuer: (servers as string[])[0] } : {}), insecure: false };
}

async function discoverAuthorizationServer(advertised: string, request: Request, set: SetCheck): Promise<{ server?: string; insecure: boolean }> {
  const issuer = parsedUrl(advertised);
  if (!issuer) {
    set("A-003", "not_checked", "Advertised authorization server URL is invalid.");
    return { insecure: false };
  }
  if (issuer.protocol !== "https:") {
    set("A-003", "not_checked", "Advertised authorization server URL is not HTTPS.");
    return { insecure: true };
  }
  const server = issuer.href.replace(/\/$/, "");
  const path = issuer.pathname === "/" ? "" : issuer.pathname.replace(/\/$/, "");
  const candidates = [`${issuer.origin}/.well-known/oauth-authorization-server${path}`, `${issuer.origin}/.well-known/openid-configuration${path}`];
  if (path) candidates.push(`${issuer.origin}${path}/.well-known/openid-configuration`);
  const fetched = await fetchMetadata(candidates, request);
  if (!fetched.fetched) return { server, insecure: false };
  if (!fetched.value) {
    set("A-003", "fail", "Authorization-server metadata is malformed JSON or not an object.");
    return { server, insecure: false };
  }
  const metadata = fetched.value;
  const present = [metadata.issuer, metadata.authorization_endpoint, metadata.token_endpoint].every((v) => typeof v === "string" && v.length > 0);
  set("A-003", present ? "pass" : "fail", present ? "Authorization-server metadata contains the required fields." : "Authorization-server metadata is missing required fields.");
  const methods = metadata.code_challenge_methods_supported;
  const s256 = Array.isArray(methods) && methods.includes("S256");
  set("A-004", methods === undefined ? "warn" : s256 ? "pass" : "fail", methods === undefined ? "PKCE methods are not advertised." : s256 ? "PKCE S256 is advertised." : "PKCE S256 is not advertised.");
  const indicators = metadata.resource_parameter_supported === true || metadata.resource_indicators_supported === true;
  set("A-005", indicators ? "pass" : "warn", indicators ? "Resource indicators are advertised." : "Resource indicator support is not advertised.");
  set("A-006", metadata.registration_endpoint === undefined ? "pass" : "warn", metadata.registration_endpoint === undefined ? "Dynamic registration is not advertised." : "Dynamic registration is advertised.");
  return { server, insecure: false };
}

async function checkCors(target: URL, request: Request, set: SetCheck): Promise<void> {
  const testOrigin = "https://evil.example";
  const response = await request(target.href, {
    method: "OPTIONS",
    requestHeaders: { origin: testOrigin, accessControlRequestMethod: "POST" },
  });
  if (!response?.ok || response.status < 200 || response.status >= 300) return;
  const origin = response.headers["access-control-allow-origin"];
  const credentials = response.headers["access-control-allow-credentials"]?.toLowerCase() === "true";
  if (origin === testOrigin) set("A-007", "fail", "CORS preflight reflects the test origin.");
  else if (origin === "*" && credentials) set("A-007", "fail", "CORS preflight advertises a wildcard and enables credentials.");
  else if (origin === "*") set("A-007", "warn", "CORS preflight advertises a wildcard without credentials.");
  else set("A-007", "pass", "CORS preflight does not allow the test origin.");
}

export async function probe(url: string): Promise<AuthProbeResult> {
  const target = parsedUrl(url);
  const checks = new Map<AuthCheckId, AuthCheck>();
  for (const { id } of AUTH_CHECKS) checks.set(id, check(id, "not_checked", "Check was not reached."));
  const set: SetCheck = (id, status, evidence) => { checks.set(id, check(id, status, evidence)); };
  const result = (authorization_server?: string): AuthProbeResult => ({ ...(authorization_server ? { authorization_server } : {}), checks: [...checks.values()] });
  if (!target || target.protocol !== "https:") {
    set("A-008", "fail", "Target URL must use HTTPS.");
    return result();
  }
  set("A-008", "pass", "All URLs considered use HTTPS.");
  const deadlineMs = Date.now() + TOTAL_BUDGET_MS;
  let count = 0;
  const request: Request = async (address, options = {}) => {
    if (count >= MAX_REQUESTS || Date.now() >= deadlineMs) return undefined;
    count++;
    return guardedFetch(address, { ...options, followRedirects: false, timeoutMs: PER_REQUEST_TIMEOUT_MS, deadlineMs, maxBytes: MAX_BODY_BYTES });
  };
  const initial = await request(target.href, { acceptStatus: [401] });
  let authorizationServer: string | undefined;
  if (initial?.ok && initial.status === 401) {
    const advertised = metadataParameter(initial.headers["www-authenticate"] ?? "");
    set("A-001", advertised !== undefined ? "pass" : "fail", advertised !== undefined ? "401 advertises protected-resource metadata." : "401 does not advertise protected-resource metadata.");
    const resource = await discoverResource(target, advertised, request, set);
    if (resource.insecure) set("A-008", "fail", "A metadata URL uses a non-HTTPS scheme.");
    if (resource.issuer) {
      const auth = await discoverAuthorizationServer(resource.issuer, request, set);
      if (auth.insecure) set("A-008", "fail", "A metadata URL uses a non-HTTPS scheme.");
      authorizationServer = auth.server;
    }
  } else if (initial?.ok && initial.status >= 200 && initial.status < 300) {
    set("A-001", "fail", "Target responds successfully without credentials.");
  }
  await checkCors(target, request, set);
  return result(authorizationServer);
}

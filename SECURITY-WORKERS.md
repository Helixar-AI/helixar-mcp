# Workers runtime — SSRF guard residual gap

The Cloudflare Workers deployment of this MCP server (`src/worker.ts`) routes
caller-supplied URLs through `src/lib/url-guard.workers.ts`, which mirrors the
contract of the Node guard at `src/lib/url-guard.ts` but with one weaker
guarantee. This document explains what that gap is, why it exists, and the
plan to close it.

## What the Workers guard enforces

Identical to the Node guard:

- HTTPS-only (http/file/ftp/ws/etc. rejected up-front).
- DNS lookup with private-range rejection — every returned address is
  classified via the shared `isPrivateAddress` in `url-classify.ts`. ANY
  private address in the answer set rejects the request. This blocks the
  classic "public+private pair" rebinding payload and any straightforward
  attempt to address an internal range by hostname.
- Bounded DNS lookup (raced against the request timeout).
- `redirect: "manual"` — every 3xx is re-validated through the same guard,
  max 3 redirect hops.
- `AbortController`-driven timeout (default 10 s).
- Streaming byte cap (default 512 KB).

## What the Workers guard does NOT enforce

**Connect-time IP pinning.** The Node guard uses an `undici.Agent` with a
custom `connect.lookup` hook that always returns the IP address we
pre-validated, so the actual TCP connect cannot be steered to a different IP
between our DNS check and the connection. The Workers `fetch()` API has no
equivalent hook — it resolves DNS again at connect time.

This means a domain whose authoritative resolver returns `203.0.113.1` for
our DoH lookup but `10.0.0.1` for Workers' subsequent resolution would slip
past the guard (DNS-rebinding TOCTOU). The window is materially narrower than
on a standard Node host because Workers' resolver is Cloudflare's
globally-cached infrastructure (not a local stub a co-tenant can poison), and
our DoH lookup also goes through Cloudflare's resolver, so both lookups
typically hit the same cache. But the gap is real in principle.

## Why we accepted this for v1

Closing the gap properly requires either:

1. `cf.resolveOverride` on the outgoing `fetch()` request — promising and
   minimal-effort, but availability across account tiers / route types is
   not yet confirmed for this deployment; or
2. Hand-rolling TLS + HTTP/1.1 (or HTTP/2) over `cloudflare:sockets` so we
   can `connect()` to a specific IP while preserving SNI / cert verification
   by hostname — multi-day work and an ongoing maintenance liability.

The pragmatic choice is to ship with the DoH-validated guard now and close
the residual gap in a follow-up. Tracked at:

- GitHub issue: [Helixar-AI/helixar-mcp#13](https://github.com/Helixar-AI/helixar-mcp/issues/13)

## Threat acceptance

For the v1 connector listing — which exposes only `helixar_inspect_mcp`
(scans MCP manifests) and `helixar_hdp_validate` (pure schema work) — the
worst-case impact of a successful TOCTOU rebind would be:

- Reading the response body of an internal endpoint addressable by hostname
  from the Cloudflare egress network, capped at 512 KB, with no auth
  injection. Workers' egress can't reach private RFC1918 / link-local space
  by IP literal; the only attack surface is a public hostname whose
  authoritative resolver is hostile.
- The body would surface in the tool's text response back to the model, not
  exfiltrated to a third party by the worker itself.

This is below the bar for a v1 launch but above zero. It must be closed
before any tool that performs authenticated outbound calls (or that
materially trusts the response body for state-changing decisions) is added
to the Workers deployment.

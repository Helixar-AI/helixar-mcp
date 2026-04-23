// Thin adapter around the ReleaseGuard CLI (`releaseguard` binary from
// github.com/Helixar-AI/ReleaseGuard). This file does NOT reimplement any
// ReleaseGuard logic — it just shells out, parses the JSON ScanResult on
// stdout, and normalises every failure mode into a structured result.
//
// Never throws. All failure modes — missing binary, non-zero exit without
// parseable output, malformed JSON — come back as `{ ok: false, reason: … }`.
//
// The JSON shape below mirrors `internal/model/result.go` and
// `internal/model/finding.go` in the ReleaseGuard repo.
//
// ── Hardening (security review S1) ─────────────────────────────────────
//   • Binary path is resolved ONCE at first use to an absolute path via
//     `HELIXAR_RELEASEGUARD_BIN` (if absolute) or `which releaseguard`.
//     A relative path — whether from env or RunOptions.binaryPath — is
//     rejected: it would re-open the $PATH-hijack attack surface that the
//     whole resolution step exists to close.
//   • spawn() receives an explicit allowlisted `env` so secret-shaped
//     parent env vars (ANTHROPIC_API_KEY, *_TOKEN, *_SECRET, …) cannot
//     leak into the child.
//   • All in-flight children are tracked in a module-level Set and
//     SIGKILL'd on parent `exit` / `SIGINT` / `SIGTERM` so a crashing
//     server never leaves a runaway `releaseguard` behind.
//   • Stderr accumulation is capped at MAX_STDERR_BYTES (truncate only,
//     no kill — stderr overflow is non-fatal) and passed through
//     `sanitiseStderr()` by the tool layer before reaching Claude.

import {
  spawn,
  execFileSync,
  type ChildProcess,
} from "node:child_process";
import { homedir } from "node:os";
import { isAbsolute } from "node:path";

export type ReleaseGuardCommand = "check" | "fix" | "harden" | "sbom";

/** Severity strings emitted by the ReleaseGuard CLI. */
export type ReleaseGuardSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info";

/** Category strings emitted by the CLI. Kept as `string` (not a union)
 *  so a newer CLI version adding a category doesn't break parsing. */
export interface ReleaseGuardFinding {
  id: string;
  category: string;
  severity: string;
  path: string;
  line?: number;
  message: string;
  evidence?: string;
  autofixable?: boolean;
  recommended_fix?: string;
  rule_id?: string;
}

export interface ReleaseGuardPolicyResult {
  result: "pass" | "warn" | "fail" | "waived";
  gates?: unknown[];
  waived?: string[];
  timestamp?: string;
}

export interface ReleaseGuardScanResult {
  version?: string;
  input_path?: string;
  manifest?: unknown;
  findings?: ReleaseGuardFinding[];
  transforms?: unknown[];
  policy_result?: ReleaseGuardPolicyResult | null;
  evidence_dir?: string;
  timestamp?: string;
  [key: string]: unknown;
}

export interface RunOptions {
  /**
   * Path to the `releaseguard` binary. Must be absolute when provided —
   * relative paths are rejected with `binary_missing` rather than silently
   * re-introducing the $PATH-hijack surface. When omitted, the module
   * uses its cached resolved path (see `getResolvedBinaryPath`).
   */
  binaryPath?: string;
  /** Override config file (--config). */
  config?: string;
  /** Hard timeout in ms; defaults to 30s. */
  timeoutMs?: number;
  /**
   * Maximum bytes of stdout to accumulate before killing the child and
   * settling with `execution_failed`. Defaults to `MAX_STDOUT_BYTES`
   * (10 MB). A pathological CLI bug or malicious binary could otherwise
   * flood memory; the timeout alone bounds the attack window but not the
   * peak allocation. Exposed primarily so tests can exercise the guard
   * with a small cap.
   */
  maxStdoutBytes?: number;
}

export type RunResult =
  | {
      ok: true;
      findings: ReleaseGuardFinding[];
      raw: ReleaseGuardScanResult;
      stderr: string;
    }
  | { ok: false; reason: "binary_missing"; stderr: string }
  | {
      ok: false;
      reason: "execution_failed";
      exitCode: number;
      stderr: string;
    }
  | {
      ok: false;
      reason: "malformed_output";
      stdout: string;
      stderr: string;
    };

const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Default cap on accumulated stdout bytes (10 MB). See `RunOptions.maxStdoutBytes`
 * for motivation — this is a memory-exhaustion guard, not a correctness check.
 * Exported so callers can reference the same constant when overriding.
 */
export const MAX_STDOUT_BYTES = 10_000_000;

/**
 * Cap on accumulated stderr bytes. Much tighter than stdout — stderr is
 * only ever user-facing diagnostic text. We truncate rather than kill the
 * child because a chatty CLI should still be allowed to finish.
 */
export const MAX_STDERR_BYTES = 4_096;

// ───────────────────────────────────────────────────────────────────────────
// Child-env allowlist
// ───────────────────────────────────────────────────────────────────────────

/**
 * Env vars we're willing to forward to the CLI child. Anything outside
 * this list — in particular ANTHROPIC_API_KEY, GITHUB_TOKEN, and any
 * *_TOKEN / *_SECRET / *_KEY / *_PASSWORD — is stripped. We deliberately
 * keep this list short: the CLI only needs locale + TMPDIR + a PATH good
 * enough to exec subprocesses of its own.
 */
const CHILD_ENV_ALLOWLIST = ["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"] as const;

export function buildChildEnv(
  parent: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const child: NodeJS.ProcessEnv = {};
  for (const key of CHILD_ENV_ALLOWLIST) {
    const value = parent[key];
    if (typeof value === "string") child[key] = value;
  }
  return child;
}

// ───────────────────────────────────────────────────────────────────────────
// Binary path resolution (cached)
// ───────────────────────────────────────────────────────────────────────────

let resolvedBinaryPath: string | null | undefined;

/**
 * Resolve and cache the absolute path to the `releaseguard` binary.
 * Precedence:
 *   1. `HELIXAR_RELEASEGUARD_BIN` env var if set and absolute.
 *   2. `which releaseguard` output.
 *   3. `null` — subsequent calls short-circuit with `binary_missing`.
 */
function resolveBinaryPath(): string | null {
  if (resolvedBinaryPath !== undefined) return resolvedBinaryPath;

  const fromEnv = process.env.HELIXAR_RELEASEGUARD_BIN;
  if (typeof fromEnv === "string" && fromEnv.length > 0 && isAbsolute(fromEnv)) {
    resolvedBinaryPath = fromEnv;
    return resolvedBinaryPath;
  }

  try {
    const out = execFileSync("which", ["releaseguard"]);
    const trimmed = out.toString("utf8").trim();
    if (trimmed.length > 0 && isAbsolute(trimmed)) {
      resolvedBinaryPath = trimmed;
      return resolvedBinaryPath;
    }
  } catch {
    // fall through to cache null
  }

  resolvedBinaryPath = null;
  return resolvedBinaryPath;
}

/** For diagnostics and tests — returns the cached resolved path (or null). */
export function getResolvedBinaryPath(): string | null {
  return resolveBinaryPath();
}

/**
 * Test seam — reset the cache so the next `resolveBinaryPath()` call
 * re-runs the precedence ladder. Not for production use.
 */
export function _resetResolvedBinaryPath(): void {
  resolvedBinaryPath = undefined;
}

// ───────────────────────────────────────────────────────────────────────────
// In-flight child tracking + parent-exit cleanup
// ───────────────────────────────────────────────────────────────────────────

const inFlightChildren = new Set<ChildProcess>();
let exitHandlersInstalled = false;

/** Test seam — observe the live set. Not for production use. */
export function _getInFlightChildren(): Set<ChildProcess> {
  return inFlightChildren;
}

function installExitHandlersOnce(): void {
  if (exitHandlersInstalled) return;
  exitHandlersInstalled = true;
  const killAll = (): void => {
    for (const child of inFlightChildren) {
      try {
        child.kill("SIGKILL");
      } catch {
        // ignore — best-effort cleanup
      }
    }
  };
  // NOTE: attaching a SIGINT / SIGTERM listener suppresses Node's default
  // terminate-on-signal behaviour. If we just killed children and returned,
  // every process importing this module (including `src/server.ts`, the MCP
  // stdio server) would stop responding to Ctrl-C and `kill` — the signal
  // would fire, children would die, and the parent would keep running. We
  // therefore explicitly re-exit with the conventional 128+signo codes.
  // The plain "exit" handler must NOT call process.exit — that would recurse.
  process.on("exit", killAll);
  process.on("SIGINT", () => {
    killAll();
    process.exit(130);
  });
  process.on("SIGTERM", () => {
    killAll();
    process.exit(143);
  });
}

// ───────────────────────────────────────────────────────────────────────────
// Stderr sanitiser
// ───────────────────────────────────────────────────────────────────────────

/**
 * Marker appended to a truncated stderr blob. The full returned string
 * (slice + marker) is guaranteed to be ≤ `maxLen` characters.
 */
const TRUNCATION_MARKER = "…[truncated]";

/**
 * Scrub + cap a stderr blob before it crosses the MCP boundary:
 *  - Replace `os.homedir()` globally with `~` so filesystem layout
 *    (usernames, project paths) doesn't leak to the caller / Claude.
 *  - Truncate to `maxLen` characters (inclusive of the marker) with a
 *    `…[truncated]` marker. The JSDoc contract is "≤ maxLen".
 */
export function sanitiseStderr(s: string, maxLen = 2_000): string {
  const home = homedir();
  let cleaned = s;
  if (home.length > 0) {
    // Escape regex metacharacters in home (the user's username might
    // contain `.` on some distros, though it's rare).
    const escaped = home.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    cleaned = cleaned.replace(new RegExp(escaped, "g"), "~");
  }
  if (cleaned.length > maxLen) {
    // Truncate so that slice + marker ≤ maxLen. If maxLen is shorter than
    // the marker itself, degenerate to a bare slice of maxLen chars.
    const keep = Math.max(0, maxLen - TRUNCATION_MARKER.length);
    cleaned =
      keep === 0
        ? cleaned.slice(0, maxLen)
        : cleaned.slice(0, keep) + TRUNCATION_MARKER;
  }
  return cleaned;
}

// ───────────────────────────────────────────────────────────────────────────
// Argv composition
// ───────────────────────────────────────────────────────────────────────────

function composeArgs(
  command: ReleaseGuardCommand,
  target: string,
  config?: string,
): string[] {
  // Flags first, `--` separator, then the positional target. Without the
  // separator, a caller-supplied target that starts with `-` (e.g. "--help",
  // "--config=…") would be parsed by cobra as a flag and alter CLI
  // behaviour — an argv-injection surface.
  const args: string[] = [command, "--format", "json"];
  if (config) args.push("--config", config);
  args.push("--", target);
  return args;
}

function tryParseScanResult(stdout: string): ReleaseGuardScanResult | null {
  const trimmed = stdout.trim();
  if (trimmed.length === 0) return null;
  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (parsed && typeof parsed === "object") {
      return parsed as ReleaseGuardScanResult;
    }
    return null;
  } catch {
    return null;
  }
}

// ───────────────────────────────────────────────────────────────────────────
// Main entry
// ───────────────────────────────────────────────────────────────────────────

export async function runReleaseGuard(
  target: string,
  command: ReleaseGuardCommand,
  options: RunOptions = {},
): Promise<RunResult> {
  // RunOptions.binaryPath wins but MUST be absolute — otherwise we'd
  // reintroduce the $PATH-hijack surface the resolution step exists to
  // close.
  let binary: string;
  if (options.binaryPath !== undefined) {
    if (!isAbsolute(options.binaryPath)) {
      return {
        ok: false,
        reason: "binary_missing",
        stderr: "binaryPath must be absolute",
      };
    }
    binary = options.binaryPath;
  } else {
    const resolved = resolveBinaryPath();
    if (resolved === null) {
      return {
        ok: false,
        reason: "binary_missing",
        stderr: "releaseguard CLI not found on PATH",
      };
    }
    binary = resolved;
  }

  const args = composeArgs(command, target, options.config);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxStdoutBytes = options.maxStdoutBytes ?? MAX_STDOUT_BYTES;

  installExitHandlersOnce();

  let child: ChildProcess;
  try {
    child = spawn(binary, args, { env: buildChildEnv(process.env) });
  } catch (err) {
    // Synchronous spawn failure is rare (usually ENOENT comes via 'error'
    // event), but guard anyway — we promised never to throw.
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: "binary_missing", stderr: msg };
  }

  inFlightChildren.add(child);

  return await new Promise<RunResult>((resolve) => {
    let stdout = "";
    let stdoutBytes = 0;
    let stderr = "";
    let stderrBytes = 0;
    let settled = false;
    const settle = (r: RunResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      inFlightChildren.delete(child);
      resolve(r);
    };

    child.stdout?.on("data", (chunk: Buffer | string) => {
      // Track byte length independently of JS string length so callers
      // using the cap to bound memory get an accurate measure regardless
      // of whether the producer sends Buffers or strings.
      const chunkBytes = Buffer.isBuffer(chunk)
        ? chunk.length
        : Buffer.byteLength(chunk);
      stdoutBytes += chunkBytes;
      if (stdoutBytes > maxStdoutBytes) {
        // Flood guard: kill the child and surface a helpful stderr.
        // Skip the string append to avoid any further allocation.
        child.kill("SIGKILL");
        settle({
          ok: false,
          reason: "execution_failed",
          exitCode: -1,
          stderr: stderr || `stdout exceeded ${maxStdoutBytes} bytes`,
        });
        return;
      }
      stdout += chunk.toString();
    });
    child.stderr?.on("data", (chunk: Buffer | string) => {
      // Stderr overflow is non-fatal — just stop appending. We don't kill
      // the child for a chatty CLI; it's allowed to finish.
      if (stderrBytes >= MAX_STDERR_BYTES) return;
      // Commit to BYTES throughout: `stderrBytes` is a byte count, so the
      // remaining budget is in bytes. Slicing `str` by character count
      // would diverge from the byte budget for multi-byte UTF-8 (e.g. a
      // 4 KB cap but 4 × 4 KB of accumulated chars). Convert to a Buffer,
      // slice on the byte boundary, decode back — the final codepoint may
      // be incomplete, which is fine for a diagnostic truncation.
      const chunkStr = chunk.toString();
      const chunkBytes = Buffer.byteLength(chunkStr);
      const remainingBytes = MAX_STDERR_BYTES - stderrBytes;
      if (chunkBytes <= remainingBytes) {
        stderr += chunkStr;
        stderrBytes += chunkBytes;
      } else {
        const buf = Buffer.from(chunkStr);
        stderr += buf.subarray(0, remainingBytes).toString("utf8");
        stderrBytes = MAX_STDERR_BYTES;
      }
    });

    child.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "ENOENT") {
        settle({ ok: false, reason: "binary_missing", stderr });
        return;
      }
      settle({
        ok: false,
        reason: "execution_failed",
        exitCode: -1,
        stderr: stderr || err.message,
      });
    });

    child.on("close", (code) => {
      const raw = tryParseScanResult(stdout);
      if (raw) {
        const findings = Array.isArray(raw.findings) ? raw.findings : [];
        settle({ ok: true, findings, raw, stderr });
        return;
      }
      if (code !== 0) {
        settle({
          ok: false,
          reason: "execution_failed",
          exitCode: code ?? -1,
          stderr,
        });
        return;
      }
      settle({ ok: false, reason: "malformed_output", stdout, stderr });
    });

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      settle({
        ok: false,
        reason: "execution_failed",
        exitCode: -1,
        stderr: stderr || `timed out after ${timeoutMs}ms`,
      });
    }, timeoutMs);
  });
}

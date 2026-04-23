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

import { spawn } from "node:child_process";

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
  /** Path to the `releaseguard` binary. Defaults to looking it up on PATH. */
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

export async function runReleaseGuard(
  target: string,
  command: ReleaseGuardCommand,
  options: RunOptions = {},
): Promise<RunResult> {
  const binary = options.binaryPath ?? "releaseguard";
  const args = composeArgs(command, target, options.config);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxStdoutBytes = options.maxStdoutBytes ?? MAX_STDOUT_BYTES;

  let child;
  try {
    child = spawn(binary, args);
  } catch (err) {
    // Synchronous spawn failure is rare (usually ENOENT comes via 'error'
    // event), but guard anyway — we promised never to throw.
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: "binary_missing", stderr: msg };
  }

  return await new Promise<RunResult>((resolve) => {
    let stdout = "";
    let stdoutBytes = 0;
    let stderr = "";
    let settled = false;
    const settle = (r: RunResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
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
      stderr += chunk.toString();
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

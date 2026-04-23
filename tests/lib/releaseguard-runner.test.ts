import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock child_process before importing the runner. Both spawn (child process
// creation) and execFileSync (used once at module-load to resolve the binary
// path via `which`) must be mocked so module import is deterministic and
// tests don't depend on whether the host has a real `releaseguard` binary.
vi.mock("node:child_process", () => ({
  spawn: vi.fn(),
  execFileSync: vi.fn(() => {
    // Default: no binary on PATH. Individual tests that exercise the
    // fallback branch reset this with mockImplementation().
    throw new Error("which: not found");
  }),
}));

// Lazy-imported after the mock is set up.
const { spawn, execFileSync } = await import("node:child_process");
const {
  runReleaseGuard,
  buildChildEnv,
  sanitiseStderr,
  getResolvedBinaryPath,
  _resetResolvedBinaryPath,
  _getInFlightChildren,
} = await import("../../src/lib/releaseguard-runner.js");

type SpawnResultKind =
  | { kind: "ok"; stdout: string; stderr?: string; exitCode?: number }
  | { kind: "enoent" }
  | { kind: "exit-nonzero"; stdout?: string; stderr?: string; exitCode: number };

function fakeChildProcess(result: SpawnResultKind): EventEmitter & {
  stdout: PassThrough;
  stderr: PassThrough;
  kill: (signal?: string) => boolean;
} {
  const emitter = new EventEmitter() as EventEmitter & {
    stdout: PassThrough;
    stderr: PassThrough;
    kill: (signal?: string) => boolean;
  };
  emitter.stdout = new PassThrough();
  emitter.stderr = new PassThrough();
  emitter.kill = () => true;

  // Emit asynchronously so listeners attach first.
  queueMicrotask(() => {
    if (result.kind === "enoent") {
      const err = Object.assign(new Error("spawn releaseguard ENOENT"), {
        code: "ENOENT",
      });
      emitter.emit("error", err);
      return;
    }
    if (result.stdout) emitter.stdout.write(result.stdout);
    if (result.stderr) emitter.stderr.write(result.stderr);
    emitter.stdout.end();
    emitter.stderr.end();
    const code = result.kind === "exit-nonzero" ? result.exitCode : (result.exitCode ?? 0);
    emitter.emit("close", code);
  });

  return emitter;
}

const mockedSpawn = vi.mocked(spawn);
const mockedExecFileSync = vi.mocked(execFileSync);

beforeEach(() => {
  mockedSpawn.mockReset();
  mockedExecFileSync.mockReset();
  // Default fallback: `which` finds /usr/local/bin/releaseguard so the
  // runner's cached resolution is a stable absolute path for the bulk of
  // tests. Tests that care about resolution semantics override this and
  // call `_resetResolvedBinaryPath()` to force re-resolution.
  mockedExecFileSync.mockReturnValue(
    Buffer.from("/usr/local/bin/releaseguard\n"),
  );
  _resetResolvedBinaryPath();
  delete process.env.HELIXAR_RELEASEGUARD_BIN;
});

afterEach(() => {
  mockedSpawn.mockReset();
  mockedExecFileSync.mockReset();
});

// A realistic ScanResult fixture, matching internal/model/result.go shape.
const FIXTURE_CLEAN = JSON.stringify({
  version: "0.1.2",
  input_path: "./dist",
  manifest: { total_files: 12 },
  findings: [],
  policy_result: { result: "pass", gates: [], waived: [], timestamp: "2026-04-23T00:00:00Z" },
  evidence_dir: "./.releaseguard/evidence",
  timestamp: "2026-04-23T00:00:00Z",
});

const FIXTURE_WITH_FINDINGS = JSON.stringify({
  version: "0.1.2",
  input_path: "./dist",
  manifest: { total_files: 42 },
  findings: [
    {
      id: "SEC-001",
      category: "secret",
      severity: "critical",
      path: "dist/bundle.js",
      line: 1337,
      message: "AWS access key embedded in bundle.",
      evidence: "AKIA…",
      autofixable: false,
    },
    {
      id: "META-003",
      category: "metadata",
      severity: "high",
      path: "dist/bundle.js.map",
      message: "Source map shipped to production.",
      autofixable: true,
      recommended_fix: "Remove before publish.",
    },
  ],
  policy_result: { result: "fail", gates: [], waived: [], timestamp: "2026-04-23T00:00:00Z" },
  evidence_dir: "./.releaseguard/evidence",
  timestamp: "2026-04-23T00:00:00Z",
});

describe("runReleaseGuard — happy path", () => {
  it("parses a clean ScanResult into an empty findings array", async () => {
    mockedSpawn.mockReturnValue(fakeChildProcess({ kind: "ok", stdout: FIXTURE_CLEAN }) as never);
    const result = await runReleaseGuard("./dist", "check");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.findings).toEqual([]);
      expect(result.raw.input_path).toBe("./dist");
      expect(result.raw.policy_result?.result).toBe("pass");
    }
  });

  it("parses findings with all fields preserved", async () => {
    mockedSpawn.mockReturnValue(
      fakeChildProcess({ kind: "ok", stdout: FIXTURE_WITH_FINDINGS }) as never,
    );
    const result = await runReleaseGuard("./dist", "check");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.findings).toHaveLength(2);
      expect(result.findings[0]?.id).toBe("SEC-001");
      expect(result.findings[0]?.severity).toBe("critical");
      expect(result.findings[0]?.line).toBe(1337);
      expect(result.findings[1]?.autofixable).toBe(true);
      expect(result.findings[1]?.recommended_fix).toBe("Remove before publish.");
    }
  });

  it("treats policy-gate non-zero exit (with valid JSON) as ok:true", async () => {
    // ReleaseGuard exits non-zero on policy fail but still emits JSON to stdout.
    mockedSpawn.mockReturnValue(
      fakeChildProcess({
        kind: "exit-nonzero",
        stdout: FIXTURE_WITH_FINDINGS,
        exitCode: 1,
      }) as never,
    );
    const result = await runReleaseGuard("./dist", "check");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.findings).toHaveLength(2);
    }
  });
});

describe("runReleaseGuard — structured error paths", () => {
  it("returns binary_missing when spawn emits ENOENT", async () => {
    mockedSpawn.mockReturnValue(fakeChildProcess({ kind: "enoent" }) as never);
    const result = await runReleaseGuard("./dist", "check");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("binary_missing");
    }
  });

  it("returns execution_failed on non-zero exit with no parseable stdout", async () => {
    mockedSpawn.mockReturnValue(
      fakeChildProcess({
        kind: "exit-nonzero",
        stdout: "",
        stderr: "releaseguard: target does not exist",
        exitCode: 2,
      }) as never,
    );
    const result = await runReleaseGuard("./does-not-exist", "check");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("execution_failed");
      if (result.reason === "execution_failed") {
        expect(result.exitCode).toBe(2);
        expect(result.stderr).toContain("target does not exist");
      }
    }
  });

  it("returns malformed_output when exit is zero but stdout is not JSON", async () => {
    mockedSpawn.mockReturnValue(
      fakeChildProcess({ kind: "ok", stdout: "not json at all" }) as never,
    );
    const result = await runReleaseGuard("./dist", "check");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("malformed_output");
    }
  });

  it("never throws — all failure modes come back as structured results", async () => {
    mockedSpawn.mockImplementation(() => {
      throw new Error("synchronous spawn failure");
    });
    const result = await runReleaseGuard("./dist", "check");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(["binary_missing", "execution_failed"]).toContain(result.reason);
    }
  });
});

describe("runReleaseGuard — argv composition", () => {
  it("places flags before the -- separator and target after", async () => {
    // Guards against argv injection: if target comes before flags, a caller
    // passing target="--help" would be parsed by cobra as a flag, not a
    // positional path. The -- separator ends flag parsing so everything
    // after it is strictly positional.
    mockedSpawn.mockReturnValue(fakeChildProcess({ kind: "ok", stdout: FIXTURE_CLEAN }) as never);
    await runReleaseGuard("./dist", "harden");
    const [binary, args] = mockedSpawn.mock.calls[0] ?? [];
    // The runner resolves the binary path at module load via `which` —
    // this matches the default mock above.
    expect(binary).toBe("/usr/local/bin/releaseguard");
    expect(args).toEqual(["harden", "--format", "json", "--", "./dist"]);
  });

  it("passes a flag-shaped target unchanged as a positional after --", async () => {
    // Regression for argv-injection: target="--help" must reach the CLI as
    // a positional arg, not be eaten by cobra as the --help flag.
    mockedSpawn.mockReturnValue(fakeChildProcess({ kind: "ok", stdout: FIXTURE_CLEAN }) as never);
    await runReleaseGuard("--help", "check");
    const [, args] = mockedSpawn.mock.calls[0] ?? [];
    expect(args).toBeDefined();
    const dashDashIndex = (args ?? []).indexOf("--");
    expect(dashDashIndex).toBeGreaterThan(-1);
    // Target must appear AFTER the -- separator.
    expect((args ?? [])[dashDashIndex + 1]).toBe("--help");
    // And before the separator there must be no bare "--help" (i.e. target
    // hasn't been duplicated into the flag section).
    const preSeparator = (args ?? []).slice(0, dashDashIndex);
    expect(preSeparator).not.toContain("--help");
  });

  it("honours binaryPath and config overrides", async () => {
    mockedSpawn.mockReturnValue(fakeChildProcess({ kind: "ok", stdout: FIXTURE_CLEAN }) as never);
    await runReleaseGuard("./dist", "check", {
      binaryPath: "/usr/local/bin/releaseguard",
      config: ".releaseguard.prod.yml",
    });
    const [binary, args] = mockedSpawn.mock.calls[0] ?? [];
    expect(binary).toBe("/usr/local/bin/releaseguard");
    expect(args).toContain("--config");
    expect(args).toContain(".releaseguard.prod.yml");
    // --config must still be on the flag side of the -- separator.
    const dashDashIndex = (args ?? []).indexOf("--");
    const configIndex = (args ?? []).indexOf("--config");
    expect(configIndex).toBeLessThan(dashDashIndex);
  });
});

describe("runReleaseGuard — stdout cap (S8)", () => {
  // Build a fake child whose stdout emits a single large chunk of bytes and
  // then stays open. The runner's cap-guard must kill the child and settle
  // with execution_failed regardless of whether the stream ever ends.
  function fakeChildEmittingStdout(chunk: string): EventEmitter & {
    stdout: PassThrough;
    stderr: PassThrough;
    kill: (signal?: string) => boolean;
    killed: boolean;
  } {
    const emitter = new EventEmitter() as EventEmitter & {
      stdout: PassThrough;
      stderr: PassThrough;
      kill: (signal?: string) => boolean;
      killed: boolean;
    };
    emitter.stdout = new PassThrough();
    emitter.stderr = new PassThrough();
    emitter.killed = false;
    emitter.kill = (_signal?: string): boolean => {
      emitter.killed = true;
      // Simulate the OS-level close that follows SIGKILL so the runner
      // won't sit on a half-open stream — though it should have already
      // settled via the cap-guard before this runs.
      queueMicrotask(() => {
        emitter.stdout.end();
        emitter.stderr.end();
        emitter.emit("close", null);
      });
      return true;
    };
    queueMicrotask(() => {
      emitter.stdout.write(chunk);
      // Intentionally do NOT end the stream — the runner must kill it.
    });
    return emitter;
  }

  it("settles with execution_failed when stdout exceeds maxStdoutBytes", async () => {
    const big = "x".repeat(500); // >> 100-byte cap
    mockedSpawn.mockReturnValue(fakeChildEmittingStdout(big) as never);
    const result = await runReleaseGuard("./dist", "check", {
      maxStdoutBytes: 100,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("execution_failed");
      if (result.reason === "execution_failed") {
        expect(result.exitCode).toBe(-1);
        // stderr should mention the cap so the caller can diagnose.
        expect(result.stderr).toMatch(/stdout exceeded/i);
        expect(result.stderr).toContain("100");
      }
    }
  });

  it("stays under cap on normal-sized output", async () => {
    // Baseline regression: FIXTURE_CLEAN is small (< 1 KB) and with the
    // default 10 MB cap should parse successfully as before.
    mockedSpawn.mockReturnValue(fakeChildProcess({ kind: "ok", stdout: FIXTURE_CLEAN }) as never);
    const result = await runReleaseGuard("./dist", "check", {
      maxStdoutBytes: 10_000_000,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.findings).toEqual([]);
      expect(result.raw.policy_result?.result).toBe("pass");
    }
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Binary-path resolution (security S1.1): pin spawn() to an absolute path
// so a malicious `releaseguard` earlier in $PATH can't hijack the server.
// ───────────────────────────────────────────────────────────────────────────
describe("runReleaseGuard — binary path resolution", () => {
  it("prefers HELIXAR_RELEASEGUARD_BIN when set to an absolute path", async () => {
    process.env.HELIXAR_RELEASEGUARD_BIN = "/opt/helixar/bin/releaseguard";
    _resetResolvedBinaryPath();
    mockedSpawn.mockReturnValue(
      fakeChildProcess({ kind: "ok", stdout: FIXTURE_CLEAN }) as never,
    );
    await runReleaseGuard("./dist", "check");
    expect(getResolvedBinaryPath()).toBe("/opt/helixar/bin/releaseguard");
    const [binary] = mockedSpawn.mock.calls[0] ?? [];
    expect(binary).toBe("/opt/helixar/bin/releaseguard");
    // `which` must NOT be consulted when the env override is valid.
    expect(mockedExecFileSync).not.toHaveBeenCalled();
  });

  it("ignores HELIXAR_RELEASEGUARD_BIN if it's a relative path and falls back to `which`", async () => {
    process.env.HELIXAR_RELEASEGUARD_BIN = "./relative/releaseguard";
    _resetResolvedBinaryPath();
    mockedExecFileSync.mockReturnValue(
      Buffer.from("/usr/local/bin/releaseguard\n"),
    );
    mockedSpawn.mockReturnValue(
      fakeChildProcess({ kind: "ok", stdout: FIXTURE_CLEAN }) as never,
    );
    await runReleaseGuard("./dist", "check");
    expect(getResolvedBinaryPath()).toBe("/usr/local/bin/releaseguard");
  });

  it("falls back to `which releaseguard` and trims the trailing newline", async () => {
    _resetResolvedBinaryPath();
    mockedExecFileSync.mockReturnValue(
      Buffer.from("/opt/homebrew/bin/releaseguard\n"),
    );
    mockedSpawn.mockReturnValue(
      fakeChildProcess({ kind: "ok", stdout: FIXTURE_CLEAN }) as never,
    );
    await runReleaseGuard("./dist", "check");
    expect(mockedExecFileSync).toHaveBeenCalledWith("which", ["releaseguard"]);
    expect(getResolvedBinaryPath()).toBe("/opt/homebrew/bin/releaseguard");
  });

  it("returns binary_missing without spawning when neither env nor `which` resolves", async () => {
    _resetResolvedBinaryPath();
    mockedExecFileSync.mockImplementation(() => {
      throw new Error("which: command not found");
    });
    const result = await runReleaseGuard("./dist", "check");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("binary_missing");
      expect(result.stderr.toLowerCase()).toContain("not found");
    }
    // Never reach spawn.
    expect(mockedSpawn).not.toHaveBeenCalled();
    // Cached as null — subsequent calls must also short-circuit without
    // re-calling `which`.
    mockedExecFileSync.mockClear();
    const again = await runReleaseGuard("./dist", "check");
    expect(again.ok).toBe(false);
    expect(mockedExecFileSync).not.toHaveBeenCalled();
  });

  it("rejects an explicit relative RunOptions.binaryPath with binary_missing", async () => {
    const result = await runReleaseGuard("./dist", "check", {
      binaryPath: "./rg",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("binary_missing");
      expect(result.stderr.toLowerCase()).toContain("absolute");
    }
    expect(mockedSpawn).not.toHaveBeenCalled();
  });

  it("accepts an explicit absolute RunOptions.binaryPath", async () => {
    mockedSpawn.mockReturnValue(
      fakeChildProcess({ kind: "ok", stdout: FIXTURE_CLEAN }) as never,
    );
    await runReleaseGuard("./dist", "check", {
      binaryPath: "/opt/custom/releaseguard",
    });
    const [binary] = mockedSpawn.mock.calls[0] ?? [];
    expect(binary).toBe("/opt/custom/releaseguard");
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Env allowlist (security S1.2): don't leak ANTHROPIC_API_KEY (or any
// other secret-shaped env var) to the child.
// ───────────────────────────────────────────────────────────────────────────
describe("runReleaseGuard — env allowlist", () => {
  it("buildChildEnv copies only the allowlisted keys", () => {
    const parent = {
      PATH: "/usr/bin:/bin",
      HOME: "/Users/tester",
      LANG: "en_GB.UTF-8",
      LC_ALL: "en_GB.UTF-8",
      TMPDIR: "/tmp",
      ANTHROPIC_API_KEY: "sk-leak",
      GITHUB_TOKEN: "ghp-leak",
      MY_SECRET: "nope",
      AWS_ACCESS_KEY_ID: "nope",
      DB_PASSWORD: "nope",
      SOME_OTHER: "nope",
    };
    const child = buildChildEnv(parent);
    expect(Object.keys(child).sort()).toEqual(
      ["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"].sort(),
    );
    expect(child.PATH).toBe("/usr/bin:/bin");
    expect(child.HOME).toBe("/Users/tester");
  });

  it("buildChildEnv skips unset allowlisted keys (no undefined values)", () => {
    const parent = { PATH: "/bin" };
    const child = buildChildEnv(parent);
    expect(child.PATH).toBe("/bin");
    expect("HOME" in child).toBe(false);
    expect("LANG" in child).toBe(false);
  });

  it("spawn call receives an env option that excludes ANTHROPIC_API_KEY", async () => {
    const saved = process.env.ANTHROPIC_API_KEY;
    process.env.ANTHROPIC_API_KEY = "sk-test-should-not-leak";
    try {
      mockedSpawn.mockReturnValue(
        fakeChildProcess({ kind: "ok", stdout: FIXTURE_CLEAN }) as never,
      );
      await runReleaseGuard("./dist", "check");
      const call = mockedSpawn.mock.calls[0];
      expect(call).toBeDefined();
      const opts = call?.[2] as { env?: NodeJS.ProcessEnv } | undefined;
      expect(opts).toBeDefined();
      expect(opts?.env).toBeDefined();
      const childEnv = opts?.env ?? {};
      expect(childEnv.ANTHROPIC_API_KEY).toBeUndefined();
      // Allowlist keys propagate if parent had them.
      expect(childEnv.PATH).toBe(process.env.PATH);
    } finally {
      if (saved === undefined) delete process.env.ANTHROPIC_API_KEY;
      else process.env.ANTHROPIC_API_KEY = saved;
    }
  });
});

// ───────────────────────────────────────────────────────────────────────────
// In-flight child tracking (security S1.3): spawned children must not
// survive the parent process. The module installs exit / SIGINT / SIGTERM
// handlers that SIGKILL every entry in the in-flight set.
// ───────────────────────────────────────────────────────────────────────────
describe("runReleaseGuard — in-flight child tracking", () => {
  it("adds the child to the in-flight set during execution and removes it on close", async () => {
    let capturedChild: EventEmitter | null = null;
    // Build a child where we can observe membership at two points: while
    // stdout is buffered (pre-close) and after close fires.
    const emitter = new EventEmitter() as EventEmitter & {
      stdout: PassThrough;
      stderr: PassThrough;
      kill: (s?: string) => boolean;
    };
    emitter.stdout = new PassThrough();
    emitter.stderr = new PassThrough();
    emitter.kill = () => true;
    capturedChild = emitter;

    mockedSpawn.mockReturnValue(emitter as never);

    const pending = runReleaseGuard("./dist", "check");
    // Yield so the runner's handlers attach and the child is registered.
    await new Promise((r) => queueMicrotask(() => r(null)));
    expect(_getInFlightChildren().has(capturedChild!)).toBe(true);
    expect(_getInFlightChildren().size).toBeGreaterThanOrEqual(1);

    emitter.stdout.write(FIXTURE_CLEAN);
    emitter.stdout.end();
    emitter.stderr.end();
    emitter.emit("close", 0);

    const result = await pending;
    expect(result.ok).toBe(true);
    // After settle, the child is purged from the set.
    expect(_getInFlightChildren().has(capturedChild!)).toBe(false);
  });

  it("removes the child from the in-flight set on error", async () => {
    const emitter = new EventEmitter() as EventEmitter & {
      stdout: PassThrough;
      stderr: PassThrough;
      kill: (s?: string) => boolean;
    };
    emitter.stdout = new PassThrough();
    emitter.stderr = new PassThrough();
    emitter.kill = () => true;
    mockedSpawn.mockReturnValue(emitter as never);
    const pending = runReleaseGuard("./dist", "check");
    await new Promise((r) => queueMicrotask(() => r(null)));
    expect(_getInFlightChildren().has(emitter)).toBe(true);
    const err = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    emitter.emit("error", err);
    await pending;
    expect(_getInFlightChildren().has(emitter)).toBe(false);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Timeout path (coverage gap): the 30 s timeout branch was never exercised
// by the existing suite. Use fake timers so the test completes instantly.
// ───────────────────────────────────────────────────────────────────────────
describe("runReleaseGuard — timeout branch", () => {
  it("settles with execution_failed when the child never closes before timeoutMs", async () => {
    vi.useFakeTimers();
    try {
      // Child that writes nothing and never closes — the runner must kill
      // it via the timeout branch.
      const emitter = new EventEmitter() as EventEmitter & {
        stdout: PassThrough;
        stderr: PassThrough;
        kill: (s?: string) => boolean;
        killed: boolean;
      };
      emitter.stdout = new PassThrough();
      emitter.stderr = new PassThrough();
      emitter.killed = false;
      emitter.kill = (_signal?: string): boolean => {
        emitter.killed = true;
        return true;
      };
      mockedSpawn.mockReturnValue(emitter as never);
      const pending = runReleaseGuard("./dist", "check", { timeoutMs: 50 });
      // Advance past the timeout.
      await vi.advanceTimersByTimeAsync(60);
      const result = await pending;
      expect(result.ok).toBe(false);
      if (!result.ok && result.reason === "execution_failed") {
        expect(result.exitCode).toBe(-1);
        expect(result.stderr).toMatch(/timed out/i);
      }
      expect(emitter.killed).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Stderr cap + sanitiser (security S1.4)
// ───────────────────────────────────────────────────────────────────────────
describe("runReleaseGuard — stderr cap", () => {
  it("truncates accumulated stderr at MAX_STDERR_BYTES but lets the child finish", async () => {
    // Emit a huge stderr (larger than the 4 KB cap) then close normally —
    // unlike stdout overflow, stderr overflow is not fatal, just truncated.
    const big = "e".repeat(10_000);
    const emitter = new EventEmitter() as EventEmitter & {
      stdout: PassThrough;
      stderr: PassThrough;
      kill: (s?: string) => boolean;
    };
    emitter.stdout = new PassThrough();
    emitter.stderr = new PassThrough();
    emitter.kill = () => true;
    mockedSpawn.mockReturnValue(emitter as never);
    queueMicrotask(() => {
      emitter.stderr.write(big);
      emitter.stderr.end();
      emitter.stdout.end();
      emitter.emit("close", 2);
    });
    const result = await runReleaseGuard("./nope", "check");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // Truncated below the raw 10 KB blob, measured in BYTES (the cap
      // is a byte budget, not a char budget).
      expect(Buffer.byteLength(result.stderr)).toBeLessThanOrEqual(4_096);
      expect(result.stderr).toContain("e");
    }
  });

  it("enforces the cap in BYTES, not chars, for multi-byte UTF-8 stderr", async () => {
    // Regression: the earlier implementation accumulated in bytes but
    // truncated by char count. A 10 000-char string of `ü` (2 bytes each)
    // is 20 000 bytes; the cap must kick in at 4 096 bytes, not 4 096
    // chars (which would leave ~8 KB accumulated past the byte budget).
    const multi = "ü".repeat(10_000); // 'ü' × 10 000 = 20 000 UTF-8 bytes
    const emitter = new EventEmitter() as EventEmitter & {
      stdout: PassThrough;
      stderr: PassThrough;
      kill: (s?: string) => boolean;
    };
    emitter.stdout = new PassThrough();
    emitter.stderr = new PassThrough();
    emitter.kill = () => true;
    mockedSpawn.mockReturnValue(emitter as never);
    queueMicrotask(() => {
      emitter.stderr.write(multi);
      emitter.stderr.end();
      emitter.stdout.end();
      emitter.emit("close", 2);
    });
    const result = await runReleaseGuard("./nope", "check");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // The BYTE length — not the char length — must satisfy the cap.
      expect(Buffer.byteLength(result.stderr)).toBeLessThanOrEqual(4_096);
    }
  });
});

describe("sanitiseStderr", () => {
  it("replaces the user's home directory with ~", () => {
    const home = process.env.HOME ?? "/home/tester";
    const raw = `error at ${home}/project/foo.js`;
    const clean = sanitiseStderr(raw);
    expect(clean).not.toContain(home);
    expect(clean).toContain("~/project/foo.js");
  });

  it("truncates so that slice + marker fit exactly within maxLen", () => {
    // The JSDoc contract is "≤ maxLen". The previous implementation
    // returned `maxLen + marker.length` — this regression-pins the fix.
    const raw = "x".repeat(5_000);
    const clean = sanitiseStderr(raw, 100);
    expect(clean.length).toBe(100);
    expect(clean).toMatch(/…\[truncated\]$/);
  });

  it("returned length is exactly maxLen for a long input", () => {
    const raw = "a".repeat(10_000);
    const clean = sanitiseStderr(raw, 256);
    expect(clean.length).toBe(256);
    expect(clean.endsWith("…[truncated]")).toBe(true);
  });

  it("leaves short strings unchanged (no truncation marker)", () => {
    const clean = sanitiseStderr("short message", 100);
    expect(clean).toBe("short message");
    expect(clean).not.toMatch(/truncated/);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Signal handler re-exit: attaching SIGINT/SIGTERM handlers suppresses
// Node's default terminate-on-signal. The handlers must therefore call
// process.exit(130|143) themselves after killing children; otherwise any
// process importing this module — including src/server.ts — would stop
// responding to Ctrl-C.
// ───────────────────────────────────────────────────────────────────────────
describe("runReleaseGuard — signal handlers re-exit", () => {
  it("SIGINT handler calls process.exit(130) after killing children", async () => {
    // The handlers are installed lazily on first runReleaseGuard() call, so
    // trigger the install by issuing a normal run first.
    mockedSpawn.mockReturnValue(
      fakeChildProcess({ kind: "ok", stdout: FIXTURE_CLEAN }) as never,
    );
    await runReleaseGuard("./dist", "check");

    const exitSpy = vi
      .spyOn(process, "exit")
      .mockImplementation(() => undefined as never);
    try {
      // Emit SIGINT synthetically — the installed listener will fire.
      process.emit("SIGINT", "SIGINT");
      expect(exitSpy).toHaveBeenCalledWith(130);
    } finally {
      exitSpy.mockRestore();
    }
  });

  it("SIGTERM handler calls process.exit(143) after killing children", async () => {
    mockedSpawn.mockReturnValue(
      fakeChildProcess({ kind: "ok", stdout: FIXTURE_CLEAN }) as never,
    );
    await runReleaseGuard("./dist", "check");

    const exitSpy = vi
      .spyOn(process, "exit")
      .mockImplementation(() => undefined as never);
    try {
      process.emit("SIGTERM", "SIGTERM");
      expect(exitSpy).toHaveBeenCalledWith(143);
    } finally {
      exitSpy.mockRestore();
    }
  });
});

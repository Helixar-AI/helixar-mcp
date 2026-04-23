import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock child_process.spawn before importing the runner.
vi.mock("node:child_process", () => ({
  spawn: vi.fn(),
}));

// Lazy-imported after the mock is set up.
const { spawn } = await import("node:child_process");
const { runReleaseGuard } = await import("../../src/lib/releaseguard-runner.js");

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

beforeEach(() => {
  mockedSpawn.mockReset();
});

afterEach(() => {
  mockedSpawn.mockReset();
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
    expect(binary).toBe("releaseguard");
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

import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock the runner — each test controls exactly what it returns.
vi.mock("../../src/lib/releaseguard-runner.js", () => ({
  runReleaseGuard: vi.fn(),
}));

const { runReleaseGuard } = await import("../../src/lib/releaseguard-runner.js");
const { releaseguard } = await import("../../src/tools/releaseguard.js");

const mockedRun = vi.mocked(runReleaseGuard);

const CLEAN_RAW = {
  version: "0.1.2",
  input_path: "./dist",
  manifest: { total_files: 12 },
  findings: [],
  policy_result: { result: "pass" as const, gates: [], waived: [], timestamp: "" },
  evidence_dir: "./.releaseguard/evidence",
};

const UNSAFE_RAW = {
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
    },
  ],
  policy_result: { result: "fail" as const, gates: [], waived: [], timestamp: "" },
  evidence_dir: "./.releaseguard/evidence",
};

beforeEach(() => {
  mockedRun.mockReset();
  delete process.env.ANTHROPIC_API_KEY;
});

describe("releaseguard — quick mode", () => {
  it("returns NONE risk on a clean scan", async () => {
    mockedRun.mockResolvedValue({
      ok: true,
      findings: [],
      raw: CLEAN_RAW,
      stderr: "",
    });
    const out = await releaseguard({ target: "./dist", mode: "quick" });
    expect("error" in out).toBe(false);
    if (!("error" in out)) {
      expect(out.risk_score).toBe(0);
      expect(out.risk_level).toBe("NONE");
      expect(out.findings).toEqual([]);
      expect(out.command).toBe("check");
      expect(typeof out.summary).toBe("string");
    }
  });

  it("computes weighted risk score from findings", async () => {
    mockedRun.mockResolvedValue({
      ok: true,
      findings: UNSAFE_RAW.findings,
      raw: UNSAFE_RAW,
      stderr: "",
    });
    const out = await releaseguard({ target: "./dist", mode: "quick" });
    if ("error" in out) throw new Error("expected success");
    // critical (40) + high (20) = 60 → HIGH bucket (50..79)
    expect(out.risk_score).toBe(60);
    expect(out.risk_level).toBe("HIGH");
    expect(out.findings).toHaveLength(2);
    expect(out.findings[0]?.rule_id).toBe("SEC-001");
  });

  it("coerces any requested command to check in quick mode", async () => {
    mockedRun.mockResolvedValue({
      ok: true,
      findings: [],
      raw: CLEAN_RAW,
      stderr: "",
    });
    await releaseguard({ target: "./dist", mode: "quick", command: "harden" });
    const firstCall = mockedRun.mock.calls[0];
    expect(firstCall).toBeDefined();
    expect(firstCall?.[1]).toBe("check");
  });

  it("quick mode ignores api_key and still runs check", async () => {
    mockedRun.mockResolvedValue({
      ok: true,
      findings: [],
      raw: CLEAN_RAW,
      stderr: "",
    });
    const out = await releaseguard({
      target: "./dist",
      mode: "quick",
      api_key: "ignored",
      command: "harden",
    });
    if ("error" in out) throw new Error("expected success");
    expect(out.command).toBe("check");
  });

  it("summary starts with [fallback] when ANTHROPIC_API_KEY is unset", async () => {
    mockedRun.mockResolvedValue({
      ok: true,
      findings: [],
      raw: CLEAN_RAW,
      stderr: "",
    });
    const out = await releaseguard({ target: "./dist", mode: "quick" });
    if ("error" in out) throw new Error("expected success");
    expect(out.summary.startsWith("[fallback]")).toBe(true);
  });
});

describe("releaseguard — deep mode auth gate", () => {
  it("rejects deep mode without an api_key", async () => {
    const out = await releaseguard({ target: "./dist", mode: "deep" });
    expect(out).toMatchObject({ error: "auth_required" });
    expect(mockedRun).not.toHaveBeenCalled();
  });

  it("rejects deep mode with an empty-string api_key", async () => {
    const out = await releaseguard({ target: "./dist", mode: "deep", api_key: "" });
    expect(out).toMatchObject({ error: "auth_required" });
    expect(mockedRun).not.toHaveBeenCalled();
  });

  it("allows any non-empty api_key through in v1", async () => {
    mockedRun.mockResolvedValue({
      ok: true,
      findings: [],
      raw: CLEAN_RAW,
      stderr: "",
    });
    const out = await releaseguard({
      target: "./dist",
      mode: "deep",
      api_key: "anything",
      command: "harden",
    });
    expect("error" in out).toBe(false);
  });
});

describe("releaseguard — deep mode commands", () => {
  it("runs harden and surfaces artifact_ref when evidence_dir is present", async () => {
    mockedRun.mockResolvedValue({
      ok: true,
      findings: [],
      raw: { ...CLEAN_RAW, evidence_dir: "./.releaseguard/evidence-abc123" },
      stderr: "",
    });
    const out = await releaseguard({
      target: "./dist",
      mode: "deep",
      api_key: "k",
      command: "harden",
    });
    if ("error" in out) throw new Error("expected success");
    expect(out.command).toBe("harden");
    expect(out.artifact_ref).toBe("./.releaseguard/evidence-abc123");
  });

  it("does not set artifact_ref on non-harden commands", async () => {
    mockedRun.mockResolvedValue({
      ok: true,
      findings: [],
      raw: CLEAN_RAW,
      stderr: "",
    });
    const out = await releaseguard({
      target: "./dist",
      mode: "deep",
      api_key: "k",
      command: "check",
    });
    if ("error" in out) throw new Error("expected success");
    expect(out.artifact_ref).toBeUndefined();
  });
});

describe("releaseguard — structured errors", () => {
  it("returns dependency_missing when the binary is absent", async () => {
    mockedRun.mockResolvedValue({
      ok: false,
      reason: "binary_missing",
      stderr: "",
    });
    const out = await releaseguard({ target: "./dist", mode: "quick" });
    expect(out).toMatchObject({ error: "dependency_missing" });
    if ("error" in out) {
      expect(out.message.toLowerCase()).toContain("releaseguard");
    }
  });

  it("returns execution_failed on a non-zero exit without parseable output", async () => {
    mockedRun.mockResolvedValue({
      ok: false,
      reason: "execution_failed",
      exitCode: 2,
      stderr: "target does not exist",
    });
    const out = await releaseguard({ target: "./nope", mode: "quick" });
    expect(out).toMatchObject({ error: "execution_failed" });
  });

  it("returns invalid_target on malformed output", async () => {
    mockedRun.mockResolvedValue({
      ok: false,
      reason: "malformed_output",
      stdout: "garbage",
      stderr: "",
    });
    const out = await releaseguard({ target: "./dist", mode: "quick" });
    expect(out).toMatchObject({ error: "invalid_target" });
  });

  it("never throws — always returns a structured shape", async () => {
    mockedRun.mockRejectedValue(new Error("synthetic"));
    const out = await releaseguard({ target: "./dist", mode: "quick" });
    expect(out).toMatchObject({ error: "execution_failed" });
  });
});

describe("releaseguard — input validation", () => {
  it("rejects an empty target with invalid_target", async () => {
    const out = await releaseguard({ target: "", mode: "quick" });
    expect(out).toMatchObject({ error: "invalid_target" });
    expect(mockedRun).not.toHaveBeenCalled();
  });
});

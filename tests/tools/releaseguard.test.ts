import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock the runner — each test controls exactly what it returns. The tool
// also imports `sanitiseStderr` from the runner module, so re-export the
// real implementation (imported at the top so the mock doesn't shadow it).
const { sanitiseStderr: realSanitiseStderr } = await vi.importActual<
  typeof import("../../src/lib/releaseguard-runner.js")
>("../../src/lib/releaseguard-runner.js");

vi.mock("../../src/lib/releaseguard-runner.js", () => ({
  runReleaseGuard: vi.fn(),
  sanitiseStderr: realSanitiseStderr,
}));

const { runReleaseGuard } = await import("../../src/lib/releaseguard-runner.js");
const { releaseguard, buildPrompt } = await import(
  "../../src/tools/releaseguard.js"
);

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

// Save + restore ANTHROPIC_API_KEY so tests that unset it don't leak across
// to other test files in the same vitest worker.
let savedAnthropicApiKey: string | undefined;

beforeEach(() => {
  mockedRun.mockReset();
  savedAnthropicApiKey = process.env.ANTHROPIC_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
});

afterEach(() => {
  if (savedAnthropicApiKey === undefined) {
    delete process.env.ANTHROPIC_API_KEY;
  } else {
    process.env.ANTHROPIC_API_KEY = savedAnthropicApiKey;
  }
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

  it("rejects deep mode with a whitespace-only api_key", async () => {
    // Review S3: a truthy-but-empty-after-trim key should not pass the
    // gate — this is the shape a tokenisation bug would emit.
    const out = await releaseguard({ target: "./dist", mode: "deep", api_key: "   " });
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

  it("does not set artifact_ref when evidence_dir is an empty string", async () => {
    // Review S2: `typeof evidence_dir === "string"` is truthy for "".
    // An empty ref is worse than omitting, so the tool must guard on length.
    mockedRun.mockResolvedValue({
      ok: true,
      findings: [],
      raw: { ...CLEAN_RAW, evidence_dir: "" },
      stderr: "",
    });
    const out = await releaseguard({
      target: "./dist",
      mode: "deep",
      api_key: "k",
      command: "harden",
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

describe("releaseguard — buildPrompt format branching", () => {
  const sampleFindings = [
    {
      rule_id: "SEC-001",
      severity: "critical",
      category: "secret",
      path: "dist/bundle.js",
      line: 1337,
      message: "AWS access key embedded in bundle.",
    },
  ];

  it("brief format instructs the model to keep output ≤250 chars", () => {
    const prompt = buildPrompt({
      target: "./dist",
      command: "check",
      findings: sampleFindings,
      riskLevel: "HIGH",
      policyResult: "fail",
      format: "brief",
    });
    // Must mention the 250-char budget so the model keeps it short.
    expect(prompt).toMatch(/250/);
    expect(prompt.toLowerCase()).toMatch(/headline|one sentence|single sentence|brief/);
  });

  it("executive format instructs the model to avoid jargon tokens", () => {
    const prompt = buildPrompt({
      target: "./dist",
      command: "check",
      findings: sampleFindings,
      riskLevel: "HIGH",
      policyResult: "fail",
      format: "executive",
    });
    // The executive variant must explicitly warn off rule-ID / CLI / hash jargon.
    expect(prompt).toMatch(/\[CVE/);
    expect(prompt).toMatch(/--fail-on/);
    expect(prompt).toMatch(/SHA/);
    // ...and should steer toward business-level risk language.
    expect(prompt.toLowerCase()).toMatch(/business|risk|non-technical|audience/);
  });

  it("technical format (default) still embeds rule IDs and paths", () => {
    const prompt = buildPrompt({
      target: "./dist",
      command: "check",
      findings: sampleFindings,
      riskLevel: "HIGH",
      policyResult: "fail",
      format: "technical",
    });
    // Rule ID must appear verbatim so the reader can grep it.
    expect(prompt).toContain("SEC-001");
    expect(prompt).toContain("dist/bundle.js");
    // And the technical prompt should NOT carry the executive "avoid jargon" block.
    expect(prompt).not.toMatch(/avoid.*jargon/i);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Target scheme validation (security): reject file://, javascript:, etc.
// and targets with embedded NUL bytes — all of which are unsafe to pass
// through to the CLI regardless of how the CLI handles them.
// ───────────────────────────────────────────────────────────────────────────
describe("releaseguard — target scheme validation", () => {
  it("rejects file:// URLs with invalid_target", async () => {
    const out = await releaseguard({
      target: "file:///etc/passwd",
      mode: "quick",
    });
    expect(out).toMatchObject({ error: "invalid_target" });
    if ("error" in out) {
      expect(out.message.toLowerCase()).toContain("file");
    }
    expect(mockedRun).not.toHaveBeenCalled();
  });

  it("rejects javascript: URLs with invalid_target", async () => {
    const out = await releaseguard({
      target: "javascript:alert(1)",
      mode: "quick",
    });
    expect(out).toMatchObject({ error: "invalid_target" });
    expect(mockedRun).not.toHaveBeenCalled();
  });

  it("rejects jar: URLs with invalid_target", async () => {
    const out = await releaseguard({
      target: "jar:file:///tmp/x.jar!/",
      mode: "quick",
    });
    expect(out).toMatchObject({ error: "invalid_target" });
    expect(mockedRun).not.toHaveBeenCalled();
  });

  it("rejects targets with embedded NUL bytes", async () => {
    const out = await releaseguard({
      target: "./dist\0/etc/passwd",
      mode: "quick",
    });
    expect(out).toMatchObject({ error: "invalid_target" });
    if ("error" in out) {
      expect(out.message.toLowerCase()).toMatch(/nul|null/);
    }
    expect(mockedRun).not.toHaveBeenCalled();
  });

  it("accepts plain absolute paths", async () => {
    mockedRun.mockResolvedValue({
      ok: true,
      findings: [],
      raw: CLEAN_RAW,
      stderr: "",
    });
    const out = await releaseguard({ target: "/var/app/dist", mode: "quick" });
    expect("error" in out).toBe(false);
  });

  it("accepts plain relative paths", async () => {
    mockedRun.mockResolvedValue({
      ok: true,
      findings: [],
      raw: CLEAN_RAW,
      stderr: "",
    });
    const out = await releaseguard({ target: "./dist", mode: "quick" });
    expect("error" in out).toBe(false);
  });

  it("accepts https:// URLs", async () => {
    mockedRun.mockResolvedValue({
      ok: true,
      findings: [],
      raw: CLEAN_RAW,
      stderr: "",
    });
    const out = await releaseguard({
      target: "https://github.com/Helixar-AI/helixar-mcp",
      mode: "quick",
    });
    expect("error" in out).toBe(false);
  });
});

// ───────────────────────────────────────────────────────────────────────────
// Stderr sanitisation — when the tool surfaces stderr from the runner it
// must first strip the user's HOME path and truncate to a safe length so
// the Claude-facing payload can't leak filesystem layout.
// ───────────────────────────────────────────────────────────────────────────
describe("releaseguard — stderr sanitisation", () => {
  it("replaces $HOME with ~ in dependency_missing stderr", async () => {
    const home = process.env.HOME ?? "/home/user";
    mockedRun.mockResolvedValue({
      ok: false,
      reason: "binary_missing",
      stderr: `not found: ${home}/bin/releaseguard`,
    });
    const out = await releaseguard({ target: "./dist", mode: "quick" });
    expect("error" in out).toBe(true);
    if ("error" in out) {
      expect(out.stderr).toBeDefined();
      expect(out.stderr).not.toContain(home);
      expect(out.stderr).toContain("~/bin/releaseguard");
    }
  });

  it("truncates long stderr and appends the marker in execution_failed", async () => {
    const huge = "x".repeat(5_000);
    mockedRun.mockResolvedValue({
      ok: false,
      reason: "execution_failed",
      exitCode: 2,
      stderr: huge,
    });
    const out = await releaseguard({ target: "./dist", mode: "quick" });
    if ("error" in out) {
      expect(out.stderr).toBeDefined();
      // Sanitised stderr is truncated to maxLen (default 2 000) + marker.
      expect((out.stderr ?? "").length).toBeLessThan(5_000);
      expect(out.stderr).toMatch(/…\[truncated\]$/);
    }
  });
});

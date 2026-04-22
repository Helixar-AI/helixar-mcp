import { describe, expect, it } from "vitest";
import { hdpValidate } from "../../src/tools/hdp-validate.js";
import type { DelegationChain } from "../../src/lib/hdp-schema.js";

const human = "user:alice@helixar.test";
const orchestrator = "agent:orchestrator-01";
const subagent = "agent:subagent-1";
const future = new Date(Date.now() + 1000 * 60 * 60).toISOString();

const cleanChain: DelegationChain = {
  root_principal: human,
  hops: [
    {
      delegator: human,
      delegatee: orchestrator,
      scope: ["read:messages", "write:summary"],
      expires_at: future,
      signature: "ed25519:abc",
      purpose: "Summarise inbox",
    },
    {
      delegator: orchestrator,
      delegatee: subagent,
      scope: ["read:messages"],
      expires_at: future,
      signature: "ed25519:def",
      purpose: "Read inbox",
    },
  ],
};

const escalationChain: DelegationChain = {
  root_principal: human,
  hops: [
    {
      delegator: human,
      delegatee: orchestrator,
      scope: ["read:messages"],
      expires_at: future,
      signature: "ed25519:abc",
      purpose: "read",
    },
    {
      delegator: orchestrator,
      delegatee: subagent,
      scope: ["read:messages", "write:admin"],
      expires_at: future,
      signature: "ed25519:def",
      purpose: "escalation attempt",
    },
  ],
};

describe("hdpValidate — draft + DOI always emitted", () => {
  it("emits draft_reference and doi on a valid chain", async () => {
    const out = await hdpValidate({ chain: cleanChain });
    expect(out.draft_reference).toBe("draft-helixar-hdp-agentic-delegation-00");
    expect(out.doi).toBe("10.5281/zenodo.19332023");
  });

  it("emits draft_reference and doi on an empty chain", async () => {
    const out = await hdpValidate({ chain: { root_principal: human, hops: [] } });
    expect(out.draft_reference).toBe("draft-helixar-hdp-agentic-delegation-00");
    expect(out.doi).toBe("10.5281/zenodo.19332023");
  });

  it("emits draft_reference and doi on a violating chain", async () => {
    const out = await hdpValidate({ chain: escalationChain });
    expect(out.draft_reference).toBe("draft-helixar-hdp-agentic-delegation-00");
    expect(out.doi).toBe("10.5281/zenodo.19332023");
  });
});

describe("hdpValidate — valid flag", () => {
  it("clean chain → valid: true, no violations", async () => {
    const out = await hdpValidate({ chain: cleanChain });
    expect(out.valid).toBe(true);
    expect(out.violations).toEqual([]);
    expect(out.scope_escalation_detected).toBe(false);
  });

  it("scope escalation → valid: false", async () => {
    const out = await hdpValidate({ chain: escalationChain });
    expect(out.valid).toBe(false);
    expect(out.scope_escalation_detected).toBe(true);
    expect(out.violations.some((v) => v.rule_id === "HDP-SCOPE-002")).toBe(true);
  });

  it("strict mode flips valid to false on a low-only chain", async () => {
    const lowOnly: DelegationChain = {
      root_principal: human,
      hops: [
        {
          delegator: human,
          delegatee: orchestrator,
          scope: ["read:messages"],
          expires_at: future,
          signature: "ed25519:abc",
          // no purpose → HDP-PURPOSE-001 (LOW)
        },
      ],
    };
    const lenient = await hdpValidate({ chain: lowOnly });
    expect(lenient.valid).toBe(true); // LOW only — passes lenient mode
    const strict = await hdpValidate({ chain: lowOnly, strict: true });
    expect(strict.valid).toBe(false);
  });
});

describe("hdpValidate — per-hop summary", () => {
  it("summarises every hop with status valid|warning|violation", async () => {
    const mixed: DelegationChain = {
      root_principal: human,
      hops: [
        {
          delegator: human,
          delegatee: orchestrator,
          scope: ["read:messages"],
          expires_at: future,
          signature: "ed25519:abc",
          purpose: "ok",
        },
        {
          delegator: orchestrator,
          delegatee: subagent,
          scope: ["read:messages"],
          expires_at: future,
          // signature missing → HDP-SIG-001 (MEDIUM = warning)
          purpose: "ok",
        },
      ],
    };
    const out = await hdpValidate({ chain: mixed });
    expect(out.hops).toHaveLength(2);
    expect(out.hops[0]?.status).toBe("valid");
    expect(out.hops[1]?.status).toBe("warning");
  });
});

describe("hdpValidate — narrative", () => {
  it("returns a narrative string (fallback prefix when no API key)", async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const out = await hdpValidate({ chain: cleanChain });
    expect(typeof out.narrative).toBe("string");
    expect(out.narrative.startsWith("[fallback]")).toBe(true);
  });
});

describe("hdpValidate — input validation", () => {
  it("rejects malformed chain shape with structured error", async () => {
    // @ts-expect-error - testing runtime guard
    const out = await hdpValidate({ chain: "not a chain object" });
    expect(out).toMatchObject({ error: "invalid_chain" });
  });
});

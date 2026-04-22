import { describe, expect, it } from "vitest";
import {
  DelegationChainSchema,
  scopeEscalationDetected,
  validateChain,
  type ChainHop,
  type DelegationChain,
} from "../../src/lib/hdp-schema.js";

const human = "user:alice@helixar.test";
const orchestrator = "agent:orchestrator-01";
const subagent1 = "agent:subagent-1";
const subagent2 = "agent:subagent-2";

const future = new Date(Date.now() + 1000 * 60 * 60).toISOString();
const past = new Date(Date.now() - 1000 * 60 * 60).toISOString();

function hop(overrides: Partial<ChainHop>): ChainHop {
  return {
    delegator: human,
    delegatee: orchestrator,
    scope: ["read:messages"],
    expires_at: future,
    signature: "ed25519:abc",
    purpose: "Summarise inbox",
    ...overrides,
  };
}

const cleanChain: DelegationChain = {
  root_principal: human,
  hops: [
    hop({ delegator: human, delegatee: orchestrator, scope: ["read:messages", "write:summary"] }),
    hop({ delegator: orchestrator, delegatee: subagent1, scope: ["read:messages"] }),
  ],
};

describe("DelegationChainSchema", () => {
  it("parses a valid chain", () => {
    const result = DelegationChainSchema.safeParse(cleanChain);
    expect(result.success).toBe(true);
  });

  it("rejects a malformed chain (non-array hops)", () => {
    const result = DelegationChainSchema.safeParse({ root_principal: human, hops: "nope" });
    expect(result.success).toBe(false);
  });

  it("accepts an empty hops list (valid no-op chain)", () => {
    const result = DelegationChainSchema.safeParse({ root_principal: human, hops: [] });
    expect(result.success).toBe(true);
  });
});

describe("validateChain — clean", () => {
  it("returns no violations on a clean two-hop chain", () => {
    const violations = validateChain(cleanChain);
    expect(violations).toEqual([]);
  });

  it("an empty chain is technically valid (no rules trigger)", () => {
    const violations = validateChain({ root_principal: human, hops: [] });
    expect(violations).toEqual([]);
  });
});

describe("validateChain — HDP-ROOT-001 (missing root_principal)", () => {
  it("fires when root_principal is missing", () => {
    const violations = validateChain({ hops: [hop({})] } as DelegationChain);
    expect(violations.some((v) => v.rule_id === "HDP-ROOT-001")).toBe(true);
  });
});

describe("validateChain — HDP-SCOPE-001 (no scope on hop)", () => {
  it("fires when a hop has empty scope", () => {
    const violations = validateChain({
      root_principal: human,
      hops: [hop({ scope: [] })],
    });
    expect(violations.some((v) => v.rule_id === "HDP-SCOPE-001")).toBe(true);
  });
});

describe("validateChain — HDP-SCOPE-002 (scope escalation)", () => {
  it("fires CRITICAL when delegatee scope ⊄ delegator scope", () => {
    const violations = validateChain({
      root_principal: human,
      hops: [
        hop({ delegator: human, delegatee: orchestrator, scope: ["read:messages"] }),
        hop({ delegator: orchestrator, delegatee: subagent1, scope: ["read:messages", "write:admin"] }),
      ],
    });
    const v = violations.find((x) => x.rule_id === "HDP-SCOPE-002");
    expect(v).toBeDefined();
    expect(v?.severity).toBe("critical");
    expect(scopeEscalationDetected(violations)).toBe(true);
  });

  it("does NOT fire when delegator has wildcard '*' scope", () => {
    const violations = validateChain({
      root_principal: human,
      hops: [
        hop({ delegator: human, delegatee: orchestrator, scope: ["*"] }),
        hop({ delegator: orchestrator, delegatee: subagent1, scope: ["anything", "else"] }),
      ],
    });
    expect(violations.some((v) => v.rule_id === "HDP-SCOPE-002")).toBe(false);
  });

  it("does NOT fire on an attenuated subset", () => {
    const violations = validateChain({
      root_principal: human,
      hops: [
        hop({ delegator: human, delegatee: orchestrator, scope: ["read:messages", "write:summary"] }),
        hop({ delegator: orchestrator, delegatee: subagent1, scope: ["read:messages"] }),
      ],
    });
    expect(violations.some((v) => v.rule_id === "HDP-SCOPE-002")).toBe(false);
    expect(scopeEscalationDetected(violations)).toBe(false);
  });
});

describe("validateChain — HDP-TTL-001 (expired hop)", () => {
  it("fires when a hop's expires_at is in the past", () => {
    const violations = validateChain({
      root_principal: human,
      hops: [hop({ expires_at: past })],
    });
    expect(violations.some((v) => v.rule_id === "HDP-TTL-001")).toBe(true);
  });
});

describe("validateChain — HDP-SIG-001 (unsigned hop)", () => {
  it("fires MEDIUM when signature is missing", () => {
    const violations = validateChain({
      root_principal: human,
      hops: [hop({ signature: undefined })],
    });
    const v = violations.find((x) => x.rule_id === "HDP-SIG-001");
    expect(v).toBeDefined();
    expect(v?.severity).toBe("medium");
  });
});

describe("validateChain — HDP-HOPS-001 (depth > 5)", () => {
  it("fires MEDIUM when chain length exceeds 5", () => {
    const longHops = [
      hop({ delegator: human, delegatee: orchestrator }),
      hop({ delegator: orchestrator, delegatee: subagent1 }),
      hop({ delegator: subagent1, delegatee: subagent2 }),
      hop({ delegator: subagent2, delegatee: "agent:s3" }),
      hop({ delegator: "agent:s3", delegatee: "agent:s4" }),
      hop({ delegator: "agent:s4", delegatee: "agent:s5" }),
    ];
    const violations = validateChain({ root_principal: human, hops: longHops });
    expect(violations.some((v) => v.rule_id === "HDP-HOPS-001")).toBe(true);
  });
});

describe("validateChain — HDP-HOPS-002 (max_hops budget)", () => {
  it("fires CRITICAL when chain length exceeds max_hops", () => {
    const violations = validateChain({
      root_principal: human,
      max_hops: 1,
      hops: [
        hop({ delegator: human, delegatee: orchestrator }),
        hop({ delegator: orchestrator, delegatee: subagent1 }),
      ],
    });
    const v = violations.find((x) => x.rule_id === "HDP-HOPS-002");
    expect(v).toBeDefined();
    expect(v?.severity).toBe("critical");
  });
});

describe("validateChain — HDP-HOP-003 (self-delegation)", () => {
  it("fires HIGH when delegator equals delegatee", () => {
    const violations = validateChain({
      root_principal: human,
      hops: [hop({ delegator: orchestrator, delegatee: orchestrator })],
    });
    expect(violations.some((v) => v.rule_id === "HDP-HOP-003")).toBe(true);
  });
});

describe("validateChain — HDP-PURPOSE-001 (missing purpose)", () => {
  it("fires LOW when a hop has no purpose", () => {
    const violations = validateChain({
      root_principal: human,
      hops: [hop({ purpose: undefined })],
    });
    const v = violations.find((x) => x.rule_id === "HDP-PURPOSE-001");
    expect(v).toBeDefined();
    expect(v?.severity).toBe("low");
  });
});

describe("validateChain — multi-violation aggregation", () => {
  it("collects every violation independently", () => {
    const violations = validateChain({
      // missing root_principal
      hops: [
        hop({ delegator: human, delegatee: orchestrator, scope: [], purpose: undefined }),
      ],
    } as DelegationChain);
    const ids = violations.map((v) => v.rule_id);
    expect(ids).toContain("HDP-ROOT-001");
    expect(ids).toContain("HDP-SCOPE-001");
    expect(ids).toContain("HDP-PURPOSE-001");
    expect(violations.length).toBeGreaterThanOrEqual(3);
  });
});

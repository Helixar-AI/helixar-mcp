// HDP delegation-chain validator.
//
// This file implements the 9 validation rules listed in the connector
// plan §3 Tool 2 against a delegation-chain abstraction. The
// connector validates *delegation patterns* (who delegated what to
// whom, with which scope, signed how) rather than the full HDP token
// signature flow — that lives in the upstream HDP SDK
// (https://github.com/Helixar-AI/HDP, src/chain/validator.ts).
//
// Where shapes overlap with the SDK we keep names in sync (HopRecord
// uses agent_id / hop_signature / parent_hop / seq there; here a
// ChainHop uses delegator/delegatee/scope/signature/expires_at because
// that's the higher-level abstraction the validator needs). A future
// pass can refactor to depend directly on @helixar/hdp once both
// stabilise — see tasks/plan.md open question #3.
//
// Rules — strictly in sync with spec §3 Tool 2:
//   HDP-ROOT-001     HIGH      §3.1   missing root_principal
//   HDP-SCOPE-001    HIGH      §4.1   no scope on hop
//   HDP-SCOPE-002    CRITICAL  §4.2   scope escalation (delegatee ⊄ delegator)
//   HDP-TTL-001      HIGH      §5.1   hop expired
//   HDP-SIG-001      MEDIUM    §6.1   unsigned hop
//   HDP-HOPS-001     MEDIUM    §4.3   chain depth > 5
//   HDP-HOPS-002     CRITICAL  §4.3   max_hops budget exhausted
//   HDP-HOP-003      HIGH      §3.4   self-delegation
//   HDP-PURPOSE-001  LOW       §3.5   missing purpose

import { z } from "zod";

// ───────────────────────────────────────────────────────────────────────────
// Schema
// ───────────────────────────────────────────────────────────────────────────

export const ChainHopSchema = z.object({
  delegator: z.string().min(1),
  delegatee: z.string().min(1),
  scope: z.array(z.string()).default([]),
  expires_at: z.string().optional(),
  signature: z.string().optional(),
  purpose: z.string().optional(),
});

export const DelegationChainSchema = z.object({
  root_principal: z.string().optional(),
  hops: z.array(ChainHopSchema).default([]),
  max_hops: z.number().int().positive().optional(),
});

export type ChainHop = z.infer<typeof ChainHopSchema>;
export type DelegationChain = z.infer<typeof DelegationChainSchema>;

// ───────────────────────────────────────────────────────────────────────────
// Violation type
// ───────────────────────────────────────────────────────────────────────────

export type HdpSeverity = "low" | "medium" | "high" | "critical";

export interface Violation {
  rule_id:
    | "HDP-ROOT-001"
    | "HDP-SCOPE-001"
    | "HDP-SCOPE-002"
    | "HDP-TTL-001"
    | "HDP-SIG-001"
    | "HDP-HOPS-001"
    | "HDP-HOPS-002"
    | "HDP-HOP-003"
    | "HDP-PURPOSE-001";
  severity: HdpSeverity;
  section: string;
  message: string;
  /** Index into chain.hops, or -1 for chain-level rules. */
  hop_index: number;
  evidence?: string;
}

// ───────────────────────────────────────────────────────────────────────────
// Validator
// ───────────────────────────────────────────────────────────────────────────

const MAX_RECOMMENDED_HOPS = 5;

export function validateChain(chain: DelegationChain): Violation[] {
  const violations: Violation[] = [];

  // Chain-level rules
  if (!chain.root_principal || chain.root_principal.trim() === "") {
    violations.push({
      rule_id: "HDP-ROOT-001",
      severity: "high",
      section: "§3.1",
      hop_index: -1,
      message: "Chain has no root_principal — delegation cannot be traced to a human or service.",
    });
  }

  if (chain.hops.length > MAX_RECOMMENDED_HOPS) {
    violations.push({
      rule_id: "HDP-HOPS-001",
      severity: "medium",
      section: "§4.3",
      hop_index: -1,
      message: `Chain depth ${chain.hops.length} exceeds the recommended maximum of ${MAX_RECOMMENDED_HOPS}.`,
      evidence: `${chain.hops.length} hops`,
    });
  }

  if (chain.max_hops !== undefined && chain.hops.length > chain.max_hops) {
    violations.push({
      rule_id: "HDP-HOPS-002",
      severity: "critical",
      section: "§4.3",
      hop_index: -1,
      message: `max_hops budget of ${chain.max_hops} is exhausted (chain has ${chain.hops.length} hops).`,
      evidence: `max_hops=${chain.max_hops}, hops=${chain.hops.length}`,
    });
  }

  // Per-hop rules
  for (let i = 0; i < chain.hops.length; i++) {
    const hop = chain.hops[i]!;
    const previousHop = i > 0 ? chain.hops[i - 1] : undefined;

    if (!hop.scope || hop.scope.length === 0) {
      violations.push({
        rule_id: "HDP-SCOPE-001",
        severity: "high",
        section: "§4.1",
        hop_index: i,
        message: "Hop has no scope declared — implies unlimited delegation.",
      });
    }

    if (previousHop && hop.scope.length > 0 && !isAttenuated(previousHop.scope, hop.scope)) {
      const escalated = hop.scope.filter((s) => !contains(previousHop.scope, s));
      violations.push({
        rule_id: "HDP-SCOPE-002",
        severity: "critical",
        section: "§4.2",
        hop_index: i,
        message:
          "Scope escalation: delegatee claims authority not granted by the delegator. " +
          "Per ZCAP-LD attenuation principle, child scope must be a subset of parent scope.",
        evidence: `escalated scopes: ${escalated.join(", ")}`,
      });
    }

    if (hop.expires_at && Date.parse(hop.expires_at) < Date.now()) {
      violations.push({
        rule_id: "HDP-TTL-001",
        severity: "high",
        section: "§5.1",
        hop_index: i,
        message: "Hop has expired — delegation must be re-issued from the root principal.",
        evidence: `expires_at=${hop.expires_at}`,
      });
    }

    if (!hop.signature || hop.signature.trim() === "") {
      violations.push({
        rule_id: "HDP-SIG-001",
        severity: "medium",
        section: "§6.1",
        hop_index: i,
        message: "Unsigned hop — chain integrity cannot be cryptographically verified.",
      });
    }

    if (hop.delegator === hop.delegatee) {
      violations.push({
        rule_id: "HDP-HOP-003",
        severity: "high",
        section: "§3.4",
        hop_index: i,
        message: "Self-delegation detected — an agent cannot delegate authority to itself.",
        evidence: `delegator=delegatee=${hop.delegator}`,
      });
    }

    if (!hop.purpose || hop.purpose.trim() === "") {
      violations.push({
        rule_id: "HDP-PURPOSE-001",
        severity: "low",
        section: "§3.5",
        hop_index: i,
        message: "No purpose declared on hop — human-readable purpose required for audit and consent.",
      });
    }
  }

  return violations;
}

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

const WILDCARD = "*";

function contains(parentScopes: string[], childScope: string): boolean {
  if (parentScopes.includes(WILDCARD)) return true;
  if (parentScopes.includes(childScope)) return true;
  // Hierarchical match: parent "read:*" should permit child "read:messages".
  for (const p of parentScopes) {
    if (p.endsWith(`:${WILDCARD}`)) {
      const prefix = p.slice(0, -1);
      if (childScope.startsWith(prefix)) return true;
    }
  }
  return false;
}

function isAttenuated(parentScopes: string[], childScopes: string[]): boolean {
  return childScopes.every((c) => contains(parentScopes, c));
}

export function scopeEscalationDetected(violations: Violation[]): boolean {
  return violations.some((v) => v.rule_id === "HDP-SCOPE-002");
}

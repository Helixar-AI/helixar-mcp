import type { HdpToken } from "@helixar_ai/hdp";
import type { DelegationChain } from "./hdp-schema.js";
import { narrate } from "./narrate.js";
import { UNTRUSTED_INSTRUCTION, untrustedBlock } from "./prompt-guard.js";

export interface ExplainInput {
  root: string;
  hops: { from: string; to: string; scope?: string[]; expires?: string }[];
  token_scope?: string[];
  token_expires?: string;
}

/** Mermaid labels are data, not markup, including HTML entity references. */
export function escapeMermaidLabel(value: string): string {
  const withoutMarkup = value.replace(/["\[\]{}()|<>`&;#\\]/g, " ");
  const withoutControls = withoutMarkup.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\u{e0000}-\u{e007f}]/gu, " ");
  return withoutControls.replace(/\s+/g, " ").trim().slice(0, 60) || "empty";
}

function limitLabel(value: string, limit: number): string {
  const clean = escapeMermaidLabel(value);
  return clean.length <= limit ? clean : `${clean.slice(0, limit - 1)}…`;
}

function tokenExpiry(milliseconds: number): string {
  // The SDK stores Unix milliseconds. Date only supports ±8.64e15 ms.
  return Number.isFinite(milliseconds) && Math.abs(milliseconds) <= 8.64e15
    ? new Date(milliseconds).toISOString()
    : String(milliseconds);
}

function tokenScope(scope: HdpToken["scope"]): string[] {
  const parts = [`intent: ${scope.intent}`];
  for (const [label, values] of [["tools", scope.authorized_tools], ["resources", scope.authorized_resources]] as const) {
    if (values?.length) {
      const visible = values.slice(0, 2).map((value) => limitLabel(value, 24));
      parts.push(`${label}: ${visible.join(", ")}${values.length > 2 ? ` (+${values.length - 2} more)` : ""}`);
    }
  }
  return parts;
}

export function fromChain(chain: DelegationChain): ExplainInput {
  return { root: chain.root_principal ?? "(missing)", hops: chain.hops.map((h) => ({ from: h.delegator, to: h.delegatee, scope: h.scope, expires: h.expires_at })) };
}

export function fromToken(token: HdpToken): ExplainInput {
  const root = token.principal.id;
  return {
    root,
    hops: token.chain.map((h, i) => ({ from: i === 0 ? root : token.chain[i - 1]!.agent_id, to: h.agent_id })),
    token_scope: tokenScope(token.scope),
    token_expires: tokenExpiry(token.header.expires_at),
  };
}

export function diagram(input: ExplainInput): string {
  const lines = ["flowchart LR"];
  // Assign identifiers independently of input so labels cannot change the graph syntax.
  const ids = new Map<string, string>();
  const node = (value: string): string => {
    let id = ids.get(value);
    if (!id) { id = `n${ids.size}`; ids.set(value, id); lines.push(`  ${id}["${escapeMermaidLabel(value)}"]`); }
    return id;
  };
  node(input.root);
  input.hops.forEach((hop, i) => {
    const from = node(hop.from), to = node(hop.to);
    const scope = hop.scope ?? (i === 0 ? input.token_scope : undefined);
    const expires = hop.expires ?? (i === 0 ? input.token_expires : undefined);
    // Reserve independent budgets so a long scope cannot hide the expiry.
    const scopeLabel = scope?.length ? `scope: ${limitLabel(scope.join(", "), expires ? 17 : 53)}` : "";
    const expiryLabel = expires ? `until: ${limitLabel(expires, scopeLabel ? 27 : 53)}` : "";
    const details = [scopeLabel, expiryLabel].filter(Boolean).join(" ");
    lines.push(details ? `  ${from} -->|"${details}"| ${to}` : `  ${from} --> ${to}`);
  });
  return lines.join("\n");
}

export async function narrative(input: ExplainInput): Promise<string> {
  // Bound both number of hops and each field before constructing the prompt.
  const hops = input.hops.slice(0, 100).map((h, i) => ({
    from: escapeMermaidLabel(h.from), to: escapeMermaidLabel(h.to),
    scope: (h.scope ?? (i === 0 ? input.token_scope : undefined))?.slice(0, 10).map(escapeMermaidLabel),
    expires: (h.expires ?? (i === 0 ? input.token_expires : undefined)),
  }));
  const safeHops = hops.map((h) => ({ ...h, expires: h.expires ? escapeMermaidLabel(h.expires) : undefined }));
  const prompt = ["Explain the following HDP delegation chain in plain language.", UNTRUSTED_INSTRUCTION,
    untrustedBlock("delegation", JSON.stringify({ root: escapeMermaidLabel(input.root), hops: safeHops, omitted_hops: input.hops.length - safeHops.length }))].join("\n\n");
  const result = await narrate(prompt, { audience: "technical", maxTokens: 320 });
  if (!result.startsWith("[fallback]")) return result;
  // Treat caller-provided identifiers as data even when narration is unavailable.
  return input.hops.map((hop, i) => {
    const scope = hop.scope ?? (i === 0 ? input.token_scope : undefined);
    const expires = hop.expires ?? (i === 0 ? input.token_expires : undefined);
    const safeScope = scope?.slice(0, 10).map(escapeMermaidLabel);
    const sentence = `${escapeMermaidLabel(hop.from)} delegated to ${escapeMermaidLabel(hop.to)}${safeScope?.length ? ` with scope ${safeScope.join(", ")}` : ""}${expires ? ` until ${escapeMermaidLabel(expires)}` : ""}.`;
    return untrustedBlock("hop", sentence);
  }).join("\n") || "No delegation hops were recorded.";
}

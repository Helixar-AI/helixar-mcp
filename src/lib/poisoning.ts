import { effectiveSchema, walkStrings } from "./manifest-schema-strings.js";
import type { MCPManifest, MCPTool, RuleCheckResult, SentinelRule } from "./sentinel-rules.js";

export const PROMPT_INJECTION_PATTERNS = [
  "ignore all previous instructions",
  "ignore previous instructions",
  "disregard the above",
  "override the system prompt",
  "you must always",
  "without confirmation",
  "unconditionally",
];

const hidden = /[\u200B-\u200F\u2060-\u2064\uFEFF\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}]/u;
const tags = /[\u{E0000}-\u{E007F}]/u;
const controls = /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2060-\u2064\uFEFF\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}]/u;
const tagPrefix = /<\/?\s*(important|system|instructions?|secret|hidden|admin)\b/i;
const concealment = /\b(do not|don't|never)\s+(tell|inform|mention|reveal|show|notify)\b[^.]{0,30}\buser\b|\bwithout (telling|informing|notifying) the user\b|\bthe user (must|should) not (know|see)\b/i;
const secretFile = /(~\/\.ssh|id_rsa|id_ed25519|\.env\b|\.aws\/credentials|mcp\.json|\.netrc|\.npmrc)/i;
const directive = /\b(when|before|after|instead of)\b[^.]{0,80}\b(call|calling|use|using|invoke|invoking)\b|\b(always|also|instead)\b[^.]{0,40}\b(send|include|cc|bcc|forward|add)\b/i;
const verbs = /\b(write|update|create|insert|modify|send|post|delete|drop|remove|purge|wipe|overwrite)\b/i;

const invariant = "Invariant Labs: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks";
const cyberArk = "CyberArk: https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe";
const trailOfBits = "Trail of Bits: https://blog.trailofbits.com/2025/07/28/we-built-the-security-layer-mcp-always-needed/";
const mcp = "MCP specification: https://modelcontextprotocol.io/specification/2025-06-18/server/tools";

export function escapeEvidence(text: string): string {
  let result = "";
  for (const character of text) {
    const escaped = controls.test(character)
      ? `U+${character.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}`
      : character;
    if (result.length + escaped.length > 80) break;
    result += escaped;
  }
  return result;
}

function hasInstruction(text: string): boolean {
  // Search only before the last closing bracket so malformed tags take linear time.
  const lastClose = text.lastIndexOf(">");
  return (lastClose >= 0 && tagPrefix.test(text.slice(0, lastClose))) ||
    concealment.test(text) || secretFile.test(text);
}

function hasLegacyInstruction(text: string): boolean {
  const lower = text.toLowerCase();
  return PROMPT_INJECTION_PATTERNS.some((pattern) => lower.includes(pattern));
}

function descriptions(tool: MCPTool): string[] {
  return [tool.name, tool.description, tool.annotations?.title ?? ""];
}

function schemaStrings(tool: MCPTool): string[] {
  return walkStrings(effectiveSchema(tool), { maxDepth: 32, maxBytes: 1_048_576 });
}

export function detectShadowing(manifest: MCPManifest, otherToolNames?: string[]): boolean {
  const candidates = manifest.tools.filter((tool) => directive.test(tool.description));
  if (candidates.length === 0) return false;

  const names = new Set((otherToolNames ?? manifest.tools.map((tool) => tool.name))
    .filter((name) => name.length >= 4).map((name) => name.toLowerCase()));
  if (names.size === 0) return false;

  // Match literal names including punctuation while allowing nearby prose.
  const escaped = [...names].map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const matcher = new RegExp(`(?<![A-Za-z0-9_])(?:${escaped.join("|")})(?![A-Za-z0-9_])`, "gi");
  return candidates.some((tool) => {
    const ownName = tool.name.toLowerCase();
    for (const match of tool.description.matchAll(matcher)) {
      if (match[0].toLowerCase() !== ownName) return true;
    }
    return false;
  });
}

function hiddenCodePoint(manifest: MCPManifest): RuleCheckResult {
  let first: string | undefined;
  for (const tool of manifest.tools) {
    for (const text of [...descriptions(tool), ...schemaStrings(tool)]) {
      const tag = tags.exec(text)?.[0];
      if (tag) return { triggered: true, severity: "critical", evidence: escapeEvidence(tag) };
      first ??= hidden.exec(text)?.[0];
    }
  }
  return first ? { triggered: true, evidence: escapeEvidence(first) } : { triggered: false };
}

function decodedInstruction(encoded: string): boolean {
  let decoded: string;
  try {
    decoded = atob(encoded);
  } catch {
    return false;
  }
  let printable = 0;
  for (let i = 0; i < decoded.length; i++) {
    const byte = decoded.charCodeAt(i);
    if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10) printable++;
  }
  return printable >= decoded.length * 0.9 &&
    (hasLegacyInstruction(decoded) || hasInstruction(decoded));
}

function encodedPayload(manifest: MCPManifest): RuleCheckResult {
  const evidence = "Encoded text in tool metadata";
  let found = false;
  for (const tool of manifest.tools) {
    for (const text of [...descriptions(tool), ...schemaStrings(tool)]) {
      for (const [encoded] of text.matchAll(/[A-Za-z0-9+/]{40,}={0,2}/g)) {
        if (decodedInstruction(encoded)) return { triggered: true, severity: "critical", evidence };
        found = true;
      }
    }
  }
  // Hex runs are also matched by the base64 character set and have medium severity.
  return { triggered: found, evidence };
}

export const POISONING_RULES: SentinelRule[] = [
  {
    id: "S-027",
    title: "Hidden Unicode characters",
    source: trailOfBits,
    severity: "high",
    category: "injection",
    mode: "deep",
    description: "Tool metadata contains invisible Unicode controls (Trail of Bits).",
    remediation: "Remove hidden characters from tool descriptions, titles, and schemas.",
    check: hiddenCodePoint,
  },
  {
    id: "S-028",
    title: "Hidden instruction blocks",
    source: invariant,
    severity: "critical",
    category: "injection",
    mode: "deep",
    description: "Tool metadata contains hidden or secret-handling instructions (Invariant Labs).",
    remediation: "Replace instructions with a plain description of what the tool does.",
    check: (manifest) => ({
      triggered: manifest.tools.some((tool) => descriptions(tool).some(hasInstruction)),
      evidence: "Hidden instruction pattern in tool metadata",
    }),
  },
  {
    id: "S-029",
    title: "Cross-tool shadowing",
    source: invariant,
    severity: "high",
    category: "injection",
    mode: "deep",
    description: "A tool description directs the caller to use another tool (Invariant Labs).",
    remediation: "Remove directions that alter the caller's use of other tools.",
    check: (manifest) => ({
      triggered: detectShadowing(manifest),
      evidence: "Directive references another tool",
    }),
  },
  {
    id: "S-030",
    title: "Encoded payloads in metadata",
    source: cyberArk,
    severity: "medium",
    category: "injection",
    mode: "deep",
    description: "Tool metadata contains an encoded string that may conceal instructions (CyberArk).",
    remediation: "Replace opaque encoded text in tool metadata with plain usage documentation.",
    check: encodedPayload,
  },
  {
    id: "S-031",
    title: "Schema embedded instructions",
    source: cyberArk,
    severity: "high",
    category: "injection",
    mode: "deep",
    description: "Tool schema strings contain instruction patterns aimed at the caller (CyberArk).",
    remediation: "Describe argument formats and constraints in schemas and remove directives.",
    check: (manifest) => ({
      triggered: manifest.tools.some((tool) =>
        schemaStrings(tool).some((text) => hasInstruction(text) || hasLegacyInstruction(text))),
      evidence: "Instruction pattern in tool schema",
    }),
  },
  {
    id: "S-032",
    title: "Contradictory tool annotations",
    source: mcp,
    severity: "medium",
    category: "authorization",
    mode: "deep",
    description: "Tool metadata suggests a write operation that may conflict with its MCP annotations.",
    remediation: "Review the behavior and set annotations that reflect the operations it performs.",
    check: (manifest) => ({
      triggered: manifest.tools.some((tool) =>
        (tool.annotations?.readOnlyHint === true || tool.annotations?.destructiveHint === false) &&
        verbs.test(`${tool.name} ${tool.description}`)),
      evidence: "Write operation may contradict annotations",
    }),
  },
];

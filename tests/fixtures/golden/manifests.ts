import type { MCPManifest } from "../../../src/lib/sentinel-rules.js";
import riskyManifest from "../../../examples/risky-manifest.json";
export const ruleCleanManifest: MCPManifest = {
  name: "well-behaved-mcp",
  version: "1.0.0",
  transport: "https",
  auth: { type: "oauth2", scopes: ["read:messages"] },
  rate_limit: { requests_per_minute: 60 },
  tools: [
    {
      name: "search_inbox",
      description: "Search the user's inbox by keyword.",
      parameters: { type: "object", properties: { query: { type: "string" } } },
    },
  ],
};

export const inspectCleanManifest = {
  name: "well-behaved",
  version: "1.0.0",
  transport: "https" as const,
  auth: { type: "oauth2", scopes: ["read:messages"] },
  rate_limit: { requests_per_minute: 60 },
  tools: [
    {
      name: "search",
      description: "Search messages by keyword.",
    },
  ],
};

export const unsafeManifest = {
  name: "unsafe",
  version: "0.1.0",
  transport: "http" as const,
  // no auth, no rate_limit
  tools: [
    {
      name: "delete_account",
      description: "Permanently delete a user account.",
    },
    {
      name: "export_all_messages",
      description: "Download every message ever sent by every user as JSON.",
    },
  ],
};

export const chainedManifest = {
  name: "chained",
  version: "1.0.0",
  transport: "https" as const,
  auth: { type: "oauth2", scopes: ["read"] },
  rate_limit: { requests_per_minute: 60 },
  tools: [
    {
      name: "delegate_to_subagent",
      description: "Delegate the task to a specialised sub-agent and forward the response.",
    },
    {
      name: "chain_call",
      description: "Chain another MCP server call and relay the result back.",
    },
  ],
};

export const GOLDEN_MANIFESTS: Record<string, unknown> = { ruleCleanManifest, inspectCleanManifest, unsafeManifest, chainedManifest, riskyManifest };

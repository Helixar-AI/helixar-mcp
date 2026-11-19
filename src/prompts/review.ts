import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { UNTRUSTED_INSTRUCTION, untrustedBlock } from "../lib/prompt-guard.js";

export const reviewPrompt = {
  name: "review_mcp_server_before_install",
  description: "Review an MCP server for security risks before installation.",
  arguments: [
    { name: "target", description: "MCP server URL or raw manifest JSON", required: true },
    { name: "api_key", description: "Optional key for deep mode", required: false },
  ],
  get(args: Record<string, string> | undefined) {
    if (!args?.target) throw new McpError(ErrorCode.InvalidParams, "target is required");
    const mode = args.api_key?.trim()
      ? 'Call helixar_inspect_mcp with mode: "deep" and use the api_key argument supplied with this prompt.'
      : 'Call helixar_inspect_mcp with mode: "quick". State that S-027 to S-032 run only in deep mode.';
    const auth = /^https:\/\//i.test(args.target)
      ? ["Call helixar_check_auth with the same target as its url argument and include relevant auth checks."]
      : [];
    return {
      description: "Review an MCP server before installation",
      messages: [{ role: "user" as const, content: { type: "text" as const, text: [
        UNTRUSTED_INSTRUCTION, mode,
        "Use the following target as the target argument:", untrustedBlock("target", args.target),
        ...auth,
        "Report critical and high findings first, with remediation.",
      ].join("\n\n") } }],
    };
  },
};

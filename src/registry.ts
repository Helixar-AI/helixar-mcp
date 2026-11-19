import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { UriTemplate } from "@modelcontextprotocol/sdk/shared/uriTemplate.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ReadResourceRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import type { ZodTypeAny } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import releaseguard from "#releaseguard";
import { catalogEntry, catalogList } from "./lib/catalog.js";
import { reviewPrompt } from "./prompts/review.js";
import { checkAuth, CheckAuthInputSchema } from "./tools/check-auth.js";
import { hdpValidate, HdpValidateInputSchema } from "./tools/hdp-validate.js";
import { hdpVerify, HdpVerifyInputSchema } from "./tools/hdp-verify.js";
import { inspectMcp, InspectMcpInputSchema } from "./tools/inspect-mcp.js";

export const SERVER_VERSION = "0.8.0";

type Surface = "stdio" | "worker";
type ToolArguments = Record<string, unknown>;

export interface ToolEntry {
  name: string;
  title: string;
  description: string;
  inputSchema: ZodTypeAny;
  annotations: Required<Pick<NonNullable<Tool["annotations"]>,
    "readOnlyHint" | "destructiveHint" | "idempotentHint" | "openWorldHint"
  >>;
  surfaces: Surface[];
  handler: (args: never) => Promise<unknown>;
}

const readOnly = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

export const TOOLS: ToolEntry[] = [
  {
    name: "helixar_inspect_mcp",
    title: "Scan MCP server",
    description:
      "Scan MCP servers (URLs or raw manifest JSON) against Helixar's Sentinel detection rules. " +
      "Returns risk scores, findings, and a security brief. Quick mode runs eight rules without " +
      "a key. Deep mode runs all 32 Sentinel rules plus composition checks with an api_key.",
    inputSchema: InspectMcpInputSchema,
    annotations: { ...readOnly, openWorldHint: true },
    surfaces: ["stdio", "worker"],
    handler: inspectMcp,
  },
  {
    name: "helixar_hdp_validate",
    title: "Check HDP chain",
    description:
      "Validate an HDP delegation chain against IETF draft-helixar-hdp-agentic-delegation-00. " +
      "Surfaces scope escalations, depth violations, expired hops, missing signatures. Every " +
      "output cites the IETF draft and Zenodo DOI.",
    inputSchema: HdpValidateInputSchema,
    annotations: { ...readOnly, openWorldHint: true },
    surfaces: ["stdio", "worker"],
    handler: hdpValidate,
  },
  {
    name: "helixar_hdp_verify",
    title: "Verify HDP token",
    description:
      "Verify a Human Delegation Provenance (HDP) token offline with the issuer's Ed25519 public key. " +
      "Reports whether the signatures and chain are intact, which integrity step failed, and the " +
      "recording period. Optional explanations may use the configured narration service. Cites the IETF draft and Zenodo DOI.",
    inputSchema: HdpVerifyInputSchema,
    annotations: { ...readOnly, openWorldHint: true },
    surfaces: ["stdio", "worker"],
    handler: hdpVerify,
  },
  {
    name: "helixar_check_auth",
    title: "Check MCP auth setup",
    description:
      "Check a public HTTPS MCP endpoint for OAuth metadata, PKCE, resource indicators, " +
      "dynamic client registration, and CORS signals. Reports eight checks with evidence and references.",
    inputSchema: CheckAuthInputSchema,
    annotations: { ...readOnly, openWorldHint: true },
    surfaces: ["stdio", "worker"],
    handler: checkAuth,
  },
];

if (releaseguard) {
  TOOLS.push({
    name: "helixar_releaseguard",
    title: "Audit release artifacts",
    description:
      "Wrap the open-source Helixar-AI/ReleaseGuard artifact policy engine. Quick mode runs " +
      "`releaseguard check` (secrets, metadata leaks, license gaps) — authless, report-only. " +
      "Deep mode unlocks the full `fix`/`harden`/`sbom` command set behind an api_key. Output " +
      "mirrors helixar_inspect_mcp: risk_score, risk_level, findings[], narrated summary.",
    inputSchema: releaseguard.schema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
    surfaces: ["stdio"],
    handler: releaseguard.handler,
  });
}

const listedTools = TOOLS.map(({ surfaces, name, title, description, inputSchema, annotations }) => ({
  surfaces,
  tool: {
    name, title, description, annotations,
    inputSchema: {
      ...zodToJsonSchema(inputSchema) as Tool["inputSchema"],
      // The Zod refinement checks the same constraint at dispatch time.
      ...(inputSchema === InspectMcpInputSchema && {
        oneOf: [{ required: ["target"] }, { required: ["targets"] }],
      }),
    },
  },
}));

export function toolsFor(surface: Surface): Tool[] {
  return listedTools.filter((entry) => entry.surfaces.includes(surface)).map((entry) => entry.tool);
}

export async function dispatch(name: string, args: ToolArguments, surface: Surface) {
  try {
    const tool = TOOLS.find((entry) => entry.name === name && entry.surfaces.includes(surface));
    if (!tool) throw new Error(`unknown tool: ${name}`);
    // Each handler validates its own input and supplies its existing error format.
    const result = await tool.handler(args as never);
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      content: [{ type: "text" as const, text: JSON.stringify({ error: "tool_failed", message }) }],
      isError: true,
    };
  }
}

export const RESOURCES = [{
  uri: "helixar://rules",
  name: "Sentinel rules",
  mimeType: "application/json",
  read: catalogList,
}];

export const RESOURCE_TEMPLATES = [{
  uriTemplate: "helixar://rules/{id}",
  name: "Sentinel rule",
  mimeType: "application/json",
  read: ({ id }: { id: string }) => catalogEntry(id),
}];

const ruleResource = RESOURCE_TEMPLATES[0]!;
const ruleUriTemplate = new UriTemplate(ruleResource.uriTemplate);

export const PROMPTS = [reviewPrompt];

export function listResources() {
  return RESOURCES.map(({ read: _read, ...entry }) => entry);
}

export function listResourceTemplates() {
  return RESOURCE_TEMPLATES.map(({ read: _read, ...entry }) => entry);
}

export function readResource(uri: string) {
  const resource = RESOURCES.find((entry) => entry.uri === uri);
  if (resource) {
    return { contents: [{ uri, mimeType: resource.mimeType, text: JSON.stringify(resource.read()) }] };
  }
  let id: string | undefined;
  try {
    const match = ruleUriTemplate.match(uri);
    if (typeof match?.id === "string") id = decodeURIComponent(match.id);
  } catch {
    // Reject a malformed percent-encoded URI with the same error as an unknown resource.
  }
  if (!id) throw new McpError(-32002, "Resource not found");
  return {
    contents: [{ uri, mimeType: ruleResource.mimeType, text: JSON.stringify(ruleResource.read({ id })) }],
  };
}

export function listPrompts() {
  return PROMPTS.map(({ get: _get, ...entry }) => entry);
}

export function getPrompt(name: string, args?: Record<string, string>) {
  const prompt = PROMPTS.find((entry) => entry.name === name);
  if (!prompt) throw new McpError(ErrorCode.InvalidParams, "Unknown prompt");
  return prompt.get(args);
}

export function registerHandlers(server: Server, surface: Surface) {
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toolsFor(surface) }));
  server.setRequestHandler(CallToolRequestSchema, async ({ params }) =>
    dispatch(params.name, params.arguments ?? {}, surface));
  server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: listResources() }));
  server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({ resourceTemplates: listResourceTemplates() }));
  server.setRequestHandler(ReadResourceRequestSchema, async ({ params }) => readResource(params.uri));
  server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: listPrompts() }));
  server.setRequestHandler(GetPromptRequestSchema, async ({ params }) => getPrompt(params.name, params.arguments));
}

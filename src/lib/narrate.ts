// Single helper used by all three Helixar MCP tools to produce
// human-readable narratives. Calls the Anthropic SDK when an API key is
// configured; otherwise (or on any SDK failure) returns a deterministic
// fallback string. Per spec §9: a Claude rate limit, network blip, or
// missing key must never break a tool call.

import Anthropic from "@anthropic-ai/sdk";

export type NarrateAudience = "executive" | "technical" | "brief" | "default";

export interface NarrateOptions {
  audience?: NarrateAudience;
  maxTokens?: number;
  /** Override the default model. */
  model?: string;
}

const DEFAULT_MODEL = "claude-haiku-4-5";
const DEFAULT_MAX_TOKENS = 320;

let warned = false;

export async function narrate(prompt: string, options: NarrateOptions = {}): Promise<string> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  const audience: NarrateAudience = options.audience ?? "default";

  if (!apiKey) {
    return fallback(prompt, audience);
  }

  try {
    const client = new Anthropic({ apiKey });
    const response = await client.messages.create({
      model: options.model ?? DEFAULT_MODEL,
      max_tokens: options.maxTokens ?? DEFAULT_MAX_TOKENS,
      messages: [{ role: "user", content: prompt }],
    });
    const textBlock = response.content.find((block) => block.type === "text");
    if (textBlock && textBlock.type === "text") {
      return textBlock.text.trim();
    }
    return fallback(prompt, audience);
  } catch (err) {
    if (!warned) {
      const message = err instanceof Error ? err.message : String(err);
      // eslint-disable-next-line no-console
      console.warn(`[helixar-mcp] narrate(): falling back to deterministic narrative (${message})`);
      warned = true;
    }
    return fallback(prompt, audience);
  }
}

// Visible-from-test reset for the warn-once guard.
export function _resetNarrateWarning(): void {
  warned = false;
}

function fallback(prompt: string, audience: NarrateAudience): string {
  // The fallback is intentionally readable: the prompt subject is preserved
  // so an operator reading the tool output can still understand what the
  // narrative was supposed to summarise. Tests assert the [fallback] prefix.
  const trimmed = prompt.trim().replace(/\s+/g, " ");
  const subject = trimmed.length > 240 ? `${trimmed.slice(0, 237)}…` : trimmed;
  const audienceTag = audience === "default" ? "" : ` (${audience})`;
  return `[fallback]${audienceTag} ${subject}`;
}

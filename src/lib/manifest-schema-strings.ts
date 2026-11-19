import type { MCPTool } from "./sentinel-rules.js";

export function effectiveSchema(tool: MCPTool): unknown {
  return tool.parameters ?? tool.inputSchema;
}

/** Walk schema keys and values, bounded by UTF-8 bytes and nesting depth. */
export function walkStrings(value: unknown, options: { maxDepth: number; maxBytes: number }): string[] {
  const out: string[] = [];
  let bytes = 0;
  function walk(v: unknown, depth: number): void {
    if (depth > options.maxDepth || bytes >= options.maxBytes) return;
    if (typeof v === "string") {
      const remaining = options.maxBytes - bytes;
      const size = Buffer.byteLength(v, "utf8");
      if (size <= remaining) {
        out.push(v);
        bytes += size;
      } else {
        const prefix = new Uint8Array(remaining);
        const { read } = new TextEncoder().encodeInto(v, prefix);
        out.push(v.slice(0, read));
        bytes = options.maxBytes;
      }
    } else if (v && typeof v === "object") {
      for (const [key, child] of Object.entries(v)) {
        if (!Array.isArray(v)) walk(key, depth + 1);
        walk(child, depth + 1);
        if (bytes >= options.maxBytes) break;
      }
    }
  }
  walk(value, 0);
  return out;
}

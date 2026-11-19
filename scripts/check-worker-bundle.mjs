import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const root = fileURLToPath(new URL("../", import.meta.url));
const wrangler = fileURLToPath(new URL("./bin/wrangler.js", import.meta.resolve("wrangler/package.json")));
const checkDir = join(root, ".wrangler-check");

// Cloudflare sets a 64 MiB uncompressed limit, checked 2026-11-20.
// https://developers.cloudflare.com/workers/platform/limits/#worker-size
const MAX_UPLOAD_BYTES = 0.75 * 64 * 1024 * 1024;
const MAX_GZIP_BYTES = 0.75 * 3 * 1024 * 1024; // Marketplace bundle budget

mkdirSync(checkDir, { recursive: true });
const outdir = mkdtempSync(join(checkDir, "bundle-"));
try {
  const result = spawnSync(process.execPath, [wrangler, "deploy", "--dry-run", "--outdir", outdir], {
    cwd: root,
    env: { ...process.env, WRANGLER_SEND_METRICS: "false" },
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Wrangler dry run failed (${result.status ?? result.signal})`);

  const files = readdirSync(outdir, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name !== "README.md" && !entry.name.endsWith(".map"));
  if (!files.some((entry) => /\.[cm]?js$/.test(entry.name))) {
    throw new Error("Wrangler produced no JavaScript bundle");
  }
  let uploadBytes = 0;
  let gzipBytes = 0;
  for (const entry of files) {
    const bundle = readFileSync(join(entry.parentPath, entry.name));
    if (/\b(?:node:)?child_process\b/.test(bundle.toString("utf8"))) {
      throw new Error(`Node child_process found in Worker bundle: ${entry.name}`);
    }
    uploadBytes += bundle.length;
    gzipBytes += gzipSync(bundle).length;
  }
  console.log(`Worker bundle: ${uploadBytes} bytes, ${gzipBytes} bytes gzip`);
  if (uploadBytes > MAX_UPLOAD_BYTES || gzipBytes > MAX_GZIP_BYTES) {
    throw new Error("Worker bundle exceeds the upload or gzip budget");
  }
} finally {
  rmSync(outdir, { recursive: true, force: true });
}

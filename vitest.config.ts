import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// The package.json `imports` field maps `#url-guard` to compiled paths in
// `dist/` (so Wrangler picks the workerd-conditioned variant at deploy
// time). Vitest runs against TypeScript source without a prior build step,
// so we alias `#url-guard` to the Node source here. Tests therefore
// exercise the same Node-runtime guard the stdio server ships with; the
// Workers guard has its own dedicated test file
// (tests/lib/url-guard-workers.test.ts) that imports it by relative path.
const urlGuardNodeSource = fileURLToPath(
  new URL("./src/lib/url-guard.ts", import.meta.url),
);

export default defineConfig({
  resolve: {
    alias: {
      "#url-guard": urlGuardNodeSource,
    },
  },
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
    coverage: {
      provider: "v8",
      reporter: ["text", "html"],
      include: ["src/**/*.ts"],
      exclude: ["src/server.ts", "src/worker.ts"],
    },
  },
});

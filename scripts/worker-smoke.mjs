import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { generateKeyPair, exportPublicKey, issueToken } from "@helixar_ai/hdp";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const wrangler = fileURLToPath(new URL("./bin/wrangler.js", import.meta.resolve("wrangler/package.json")));
const base = "http://127.0.0.1:8787";

const child = spawn(process.execPath, [
  wrangler, "dev", "--local", "--ip", "127.0.0.1", "--port", "8787",
  "--env-file", process.platform === "win32" ? "NUL" : "/dev/null",
  "--show-interactive-dev-session=false",
], {
  cwd: root,
  env: {
    ...process.env,
    ANTHROPIC_API_KEY: "",
    CLOUDFLARE_INCLUDE_PROCESS_ENV: "false",
    CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV: "false",
    WRANGLER_SEND_METRICS: "false",
  },
  stdio: ["ignore", "pipe", "pipe"],
});

let logs = "";
let exitReason;
const stopped = new Promise((resolve) => {
  child.once("close", (code, signal) => {
    exitReason = `exit ${code ?? signal}`;
    resolve();
  });
  child.once("error", (error) => {
    exitReason = error.message;
    resolve();
  });
});
for (const stream of [child.stdout, child.stderr]) {
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => { logs = (logs + chunk).slice(-16_000); });
}

async function waitForHealth() {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline && !exitReason) {
    if (logs.includes(`Ready on ${base}`)) {
      const response = await fetch(`${base}/health`, { signal: AbortSignal.timeout(1_000) }).catch(() => null);
      if (response?.ok && (await response.json()).name === "helixar-mcp") return;
    }
    await delay(250);
  }
  throw new Error(`Worker failed to start (${exitReason ?? "health probe timed out"})\n${logs}`);
}

const client = new Client({ name: "helixar-worker-smoke", version: "1.0.0" });
const options = { timeout: 10_000 };

async function callTool(name, args) {
  const result = await client.callTool({ name, arguments: args }, undefined, options);
  assert.ok(!result.isError, `${name} returned an MCP tool error`);
  assert.equal(result.content?.[0]?.type, "text");
  return JSON.parse(result.content[0].text);
}

try {
  await waitForHealth();
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`)), options);
  const { tools } = await client.listTools({}, options);
  const expected = {
    helixar_inspect_mcp: ["Scan MCP server", true],
    helixar_hdp_validate: ["Check HDP chain", false],
    helixar_hdp_verify: ["Verify HDP token", false],
  };
  assert.deepEqual(tools.map(({ name }) => name).sort(), Object.keys(expected).sort());
  for (const { name, title, annotations } of tools) {
    const [expectedTitle, openWorldHint] = expected[name];
    assert.equal(title, expectedTitle);
    assert.deepEqual(annotations, {
      readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint,
    });
  }

  const target = await readFile(new URL("../examples/risky-manifest.json", import.meta.url), "utf8");
  const scan = await callTool("helixar_inspect_mcp", { target, mode: "deep", api_key: "smoke" });
  assert.ok(scan.findings.some(({ rule_id }) => rule_id === "S-004"));
  assert.ok(scan.findings.every(({ refs }) => refs && Object.keys(refs).length));

  const targets = [
    { name: "account-data", tools: [{ name: "get_customer" }] },
    { name: "web-content", tools: [{ name: "read_page" }] },
    { name: "notifications", tools: [{ name: "send_notice" }] },
  ].map((manifest) => JSON.stringify(manifest));
  const composed = await callTool("helixar_inspect_mcp", { targets, mode: "deep", api_key: "smoke" });
  assert.equal(composed.servers.length, targets.length);
  assert.ok(composed.combined.findings.some(({ rule_id }) => rule_id === "T-002"));

  const chain = await callTool("helixar_hdp_validate", {
    chain: {
      root_principal: "smoke-user",
      hops: [
        { delegator: "smoke-user", delegatee: "agent-one", scope: ["read"], signature: "example" },
        { delegator: "agent-one", delegatee: "agent-two", scope: ["read"], signature: "example" },
      ],
    },
  });
  assert.equal(chain.valid, true);
  assert.equal(chain.hops.length, 2);

  const { privateKey, publicKey } = await generateKeyPair();
  const token = await issueToken({
    sessionId: "worker-smoke",
    principal: { id: "smoke-user", id_type: "opaque" },
    scope: {
      intent: "Worker smoke test", data_classification: "public",
      network_egress: false, persistence: false,
    },
    signingKey: privateKey,
    keyId: "worker-smoke",
  });
  const audit = await callTool("helixar_hdp_verify", { token, public_key: exportPublicKey(publicKey) });
  assert.equal(audit.valid, true, JSON.stringify(audit));
  assert.equal(audit.issuer, "smoke-user");

  const { resources } = await client.listResources({}, options);
  assert.ok(resources.some(({ uri }) => uri === "helixar://rules"));
  const { resourceTemplates } = await client.listResourceTemplates({}, options);
  assert.ok(resourceTemplates.some(({ uriTemplate }) => uriTemplate === "helixar://rules/{id}"));
  const { contents } = await client.readResource({ uri: "helixar://rules/S-027" }, options);
  assert.equal(JSON.parse(contents[0].text).id, "S-027");

  const { prompts } = await client.listPrompts({}, options);
  const name = "review_mcp_server_before_install";
  assert.ok(prompts.some((prompt) => prompt.name === name));
  const prompt = await client.getPrompt({ name, arguments: { target } }, options);
  assert.match(prompt.messages[0].content.text, /mode: "quick"/);

  console.log("Worker smoke passed: every Worker tool, rule resources, and review prompt");
} finally {
  try {
    await client.close();
  } finally {
    child.kill("SIGTERM");
    const exited = await Promise.race([stopped.then(() => true), delay(2_000, false, { ref: false })]);
    if (!exited) child.kill("SIGKILL");
  }
}

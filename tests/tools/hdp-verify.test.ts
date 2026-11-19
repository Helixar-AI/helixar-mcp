import { beforeEach, describe, expect, it, vi } from "vitest";
import { auditToken, exportPublicKey, extendChain, generateKeyPair, HdpSchemaError, issueToken } from "@helixar_ai/hdp";
import { hdpVerify } from "../../src/tools/hdp-verify.js";

vi.mock("@helixar_ai/hdp", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@helixar_ai/hdp")>();
  return { ...actual, auditToken: vi.fn(actual.auditToken) };
});

async function fixture() {
  const keys = await generateKeyPair();
  const issued = await issueToken({
    sessionId: "test-session",
    principal: { id: "test-principal", id_type: "opaque" },
    scope: { intent: "test", authorized_tools: ["test"], authorized_resources: ["*"], data_classification: "public", network_egress: false, persistence: false, max_hops: 2 },
    signingKey: keys.privateKey,
    keyId: "test-key",
  });
  const token = await extendChain(issued, { agent_id: "test-agent", agent_type: "orchestrator", action_summary: "test", parent_hop: 0 }, keys.privateKey);
  return { token, key: exportPublicKey(keys.publicKey) };
}

beforeEach(() => vi.mocked(auditToken).mockClear());

describe("hdpVerify", () => {
  it("verifies an issued token and reports its shape", async () => {
    const { token, key } = await fixture();
    const out = await hdpVerify({ token, public_key: key });
    expect(out).toMatchObject({ valid: true, issuer: "test-principal", hop_count: 1, recording_period: "within_period", recorded_after_period: [] });
    expect(vi.mocked(auditToken)).toHaveBeenCalledTimes(1);
  });

  it("reports the SDK's failed step when a hop signature is changed", async () => {
    const { token, key } = await fixture();
    const signature = token.chain[0]!.hop_signature;
    token.chain[0]!.hop_signature = (signature[0] === "A" ? "B" : "A") + signature.slice(1);
    const sdk = await auditToken(token, { publicKey: (await import("@helixar_ai/hdp")).importPublicKey(key) });
    const out = await hdpVerify({ token, public_key: key });
    expect(sdk.integrity.status).toBe("invalid");
    if (sdk.integrity.status !== "invalid") throw new Error("expected invalid audit");
    expect(out).toMatchObject({ valid: false, failed_step: sdk.integrity.failedStep });
    expect(JSON.stringify(out)).not.toContain(sdk.integrity.error.message);
  });

  it("rejects a wrong key", async () => {
    const { token } = await fixture();
    const other = await generateKeyPair();
    expect((await hdpVerify({ token, public_key: exportPublicKey(other.publicKey) })).valid).toBe(false);
  });

  it("rejects oversized strings and objects before audit", async () => {
    expect((await hdpVerify({ token: "x".repeat(65_537), public_key: "x" })).error?.code).toBe("token_too_large");
    expect((await hdpVerify({ token: { data: "x".repeat(65_537) }, public_key: "x" })).error?.code).toBe("token_too_large");
    expect(auditToken).not.toHaveBeenCalled();
  });

  it("rejects malformed keys and invalid JSON", async () => {
    for (const key of ["***", exportPublicKey(new Uint8Array(31)), "A".repeat(42) + "B"]) {
      expect((await hdpVerify({ token: {}, public_key: key })).error?.code).toBe("invalid_public_key");
    }
    expect((await hdpVerify({ token: "{", public_key: "x" })).error?.code).toBe("invalid_token_json");
    expect(auditToken).not.toHaveBeenCalled();
  });

  it("passes the original JSON to the SDK so duplicate keys are rejected", async () => {
    const { token, key } = await fixture();
    const json = JSON.stringify(token).replace('{"hdp":', '{"hdp":"duplicate","hdp":');
    expect(json).not.toBe(JSON.stringify(token));
    const out = await hdpVerify({ token: json, public_key: key });
    expect(out).toMatchObject({ valid: false, failed_step: 0, error: { code: "schema_invalid" } });
    expect(auditToken).toHaveBeenCalledWith(json, expect.anything());
  });

  it("sanitizes errors returned or thrown by the SDK", async () => {
    const { token, key } = await fixture();
    const secret = "sensitive SDK detail";
    vi.mocked(auditToken).mockRejectedValueOnce(new HdpSchemaError(secret));
    const thrown = await hdpVerify({ token, public_key: key });
    expect(thrown.error?.code).toBe("schema_invalid");
    expect(JSON.stringify(thrown)).not.toContain(secret);
    vi.mocked(auditToken).mockRejectedValueOnce(new Error(secret));
    const unknown = await hdpVerify({ token, public_key: key });
    expect(unknown.error?.code).toBe("verify_failed");
    expect(JSON.stringify(unknown)).not.toContain(secret);
    const returned = await hdpVerify({ token: {}, public_key: key });
    expect(returned).toMatchObject({ valid: false, failed_step: 0, error: { code: "schema_invalid" } });
    expect(JSON.stringify(returned)).not.toContain("SCHEMA_INVALID");
  });
});

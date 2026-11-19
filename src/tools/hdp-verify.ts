import {
  auditToken,
  HdpChainIntegrityError,
  HdpSchemaError,
  HdpSignatureInvalidError,
  HdpTokenExpiredError,
} from "@helixar_ai/hdp";
import { z } from "zod";
import { escapeEvidence } from "../lib/poisoning.js";
import { HDP_DOI, HDP_DRAFT_REFERENCE } from "./hdp-validate.js";

const MAX_TOKEN_BYTES = 65_536;

export const HdpVerifyInputSchema = z.object({
  token: z.union([z.string(), z.record(z.unknown())]),
  public_key: z.string(),
});
export type HdpVerifyInput = z.infer<typeof HdpVerifyInputSchema>;

type VerifyError = { code: string; message: string };
export interface HdpVerifyOutput {
  valid: boolean;
  failed_step?: number;
  error?: VerifyError;
  issuer?: string;
  hop_count?: number;
  recording_period?: "within_period" | "recorded_after_period" | "not_checked";
  recorded_after_period?: number[];
  draft_reference: typeof HDP_DRAFT_REFERENCE;
  doi: typeof HDP_DOI;
}

const citations = { draft_reference: HDP_DRAFT_REFERENCE, doi: HDP_DOI } as const;
function failure(code: string, message: string): HdpVerifyOutput {
  return { valid: false, error: { code, message }, ...citations };
}

function safeError(error: unknown): VerifyError {
  if (error instanceof HdpSchemaError) return { code: "schema_invalid", message: "Token schema is invalid" };
  if (error instanceof HdpSignatureInvalidError) return { code: "signature_invalid", message: "Token signature is invalid" };
  if (error instanceof HdpChainIntegrityError) return { code: "chain_invalid", message: "Token chain integrity is invalid" };
  if (error instanceof HdpTokenExpiredError) return { code: "expired", message: "Token has expired" };
  return { code: "verify_failed", message: "Token verification failed" };
}

function decodeKey(key: string): Uint8Array | undefined {
  // Ed25519 public keys encode as exactly 43 unpadded base64url characters.
  if (!/^[A-Za-z0-9_-]{43}$/.test(key)) return undefined;
  try {
    const decoded = atob(key.replace(/-/g, "+").replace(/_/g, "/") + "=");
    const canonical = btoa(decoded).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    if (decoded.length !== 32 || canonical !== key) return undefined;
    return Uint8Array.from(decoded, (char) => char.charCodeAt(0));
  } catch {
    return undefined;
  }
}

export async function hdpVerify(input: HdpVerifyInput): Promise<HdpVerifyOutput> {
  const parsed = HdpVerifyInputSchema.safeParse(input);
  if (!parsed.success) return failure("invalid_input", "Token and public key are required");
  const { token, public_key } = parsed.data;
  let serialized: string;
  try {
    serialized = typeof token === "string" ? token : JSON.stringify(token);
  } catch {
    return failure("invalid_input", "Token must be JSON serializable");
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_TOKEN_BYTES) {
    return failure("token_too_large", "Token exceeds 65,536 bytes");
  }
  let object: unknown = token;
  if (typeof token === "string") {
    try {
      object = JSON.parse(token) as unknown;
    } catch {
      return failure("invalid_token_json", "token is not valid JSON");
    }
  }
  const publicKey = decodeKey(public_key);
  if (!publicKey) return failure("invalid_public_key", "Public key must be a base64url-encoded 32-byte Ed25519 key");
  try {
    // Keep the serialized input intact so the SDK can reject duplicate object keys.
    const audit = await auditToken(token, { publicKey });
    const out: HdpVerifyOutput = {
      valid: audit.integrity.status === "valid",
      recording_period: audit.recordingPeriod.status,
      recorded_after_period: audit.recordingPeriod.status === "recorded_after_period" ? audit.recordingPeriod.hopSeqs : [],
      ...citations,
    };
    if (audit.integrity.status === "invalid") {
      out.failed_step = audit.integrity.failedStep;
      out.error = safeError(audit.integrity.error);
    }
    if (object && typeof object === "object" && !Array.isArray(object)) {
      const candidate = object as Record<string, unknown>;
      const principal = candidate.principal;
      if (principal && typeof principal === "object" && "id" in principal && typeof principal.id === "string") {
        out.issuer = escapeEvidence(principal.id);
      }
      if (Array.isArray(candidate.chain)) out.hop_count = candidate.chain.length;
    }
    return out;
  } catch (error) {
    return { valid: false, error: safeError(error), ...citations };
  }
}

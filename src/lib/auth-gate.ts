// Single choke-point for the "deep mode requires a non-empty api_key" check.
//
// Every tool that exposes a quick/deep tier MUST call requireDeepAuth()
// before touching its rule set. Duplicating the check per tool invited
// drift (a new tool forgetting the check, or the check evolving in one
// place but not others). This module is that one place.
//
// v1 accepts any non-empty, trimmed string as a valid key. Real OAuth
// validation lands with the Worker adapter in Phase 7.

export interface AuthRequiredError {
  error: "auth_required";
  message: string;
}

export type Mode = "quick" | "deep";

const GATE_MESSAGE =
  "deep mode requires an api_key — quick mode is the public/authless tier";

/**
 * Returns `null` when the mode/key combination is allowed to proceed.
 * Returns a structured `auth_required` error otherwise.
 *
 * The supplied `api_key` value is NEVER included in the returned message —
 * callers can log the result verbatim without leaking the caller's key
 * (or anything that looked like a key) back to the user.
 */
export function requireDeepAuth(
  mode: Mode,
  api_key: string | undefined,
): AuthRequiredError | null {
  if (mode === "deep" && !api_key?.trim()) {
    return { error: "auth_required", message: GATE_MESSAGE };
  }
  return null;
}

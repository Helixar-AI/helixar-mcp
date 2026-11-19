import { z } from "zod";
import { probe, type AuthStatus } from "../lib/auth-probe.js";

const invalidUrl = "URL must be an HTTPS URL without credentials, query, or fragment.";
export const CheckAuthInputSchema = z.object({
  url: z.string().url().refine((value) => {
    if (!/^https:\/\//i.test(value)) return false;
    try {
      const url = new URL(value);
      return !url.username && !url.password && !url.search && !url.hash;
    } catch {
      return false;
    }
  }, invalidUrl),
});
export type CheckAuthInput = z.infer<typeof CheckAuthInputSchema>;
export async function checkAuth(input: CheckAuthInput) {
  const parsed = CheckAuthInputSchema.safeParse(input);
  if (!parsed.success) return { error: "invalid_url" as const, message: invalidUrl };
  const { authorization_server, checks } = await probe(parsed.data.url);
  const summary: Record<AuthStatus, number> = { pass: 0, fail: 0, warn: 0, inferred: 0, not_checked: 0 };
  for (const item of checks) summary[item.status]++;
  return { target: parsed.data.url, ...(authorization_server ? { authorization_server } : {}), checks, summary };
}

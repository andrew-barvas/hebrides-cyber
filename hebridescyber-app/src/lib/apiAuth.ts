// Shared caller resolution for the public REST API (/api/v1/*).
//
// Accepts two credential types against the same routes:
//   - an API key   (Authorization: Bearer hc_live_…) — CI, scripts, the Action
//   - a session JWT (Authorization: Bearer <supabase jwt>) — the dashboard
//
// Both resolve to the same { ownerId } so route handlers never branch on how
// the caller authenticated.
import type { NextApiRequest } from "next";
import { looksLikeApiKey, resolveApiKey } from "./apiKeys";
import { getSupabaseAdmin, supabaseAdmin } from "./supabaseAdmin";

export { supabaseAdmin };

export type ApiCaller = {
  ownerId: string;
  /** How the caller authenticated — used to gate key management to sessions. */
  via: "key" | "session";
};

export async function authenticateApiRequest(req: NextApiRequest): Promise<ApiCaller | null> {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return null;
  const token = auth.slice(7).trim();
  if (!token) return null;

  // A bad credential is a 401, never a 500 — so a malformed token, an unknown
  // key, or an unreachable Supabase all resolve to "not authenticated" rather
  // than surfacing an exception (and a stack trace) to the caller.
  try {
    if (looksLikeApiKey(token)) {
      const resolved = await resolveApiKey(getSupabaseAdmin(), token);
      return resolved ? { ownerId: resolved.ownerId, via: "key" } : null;
    }

    const { data, error } = await getSupabaseAdmin().auth.getUser(token);
    if (error || !data.user) return null;
    return { ownerId: data.user.id, via: "session" };
  } catch {
    return null;
  }
}

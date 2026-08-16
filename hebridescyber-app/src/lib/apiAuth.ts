// Shared caller resolution for the public REST API (/api/v1/*).
//
// Accepts two credential types against the same routes:
//   - an API key   (Authorization: Bearer hc_live_…) — CI, scripts, the Action
//   - a session JWT (Authorization: Bearer <supabase jwt>) — the dashboard
//
// Both resolve to the same { ownerId } so route handlers never branch on how
// the caller authenticated.
import type { NextApiRequest } from "next";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { looksLikeApiKey, resolveApiKey } from "./apiKeys";

// Constructed on first use, not at import. createClient() throws when the URL
// is empty, and doing that at module scope turns a missing env var into a
// Next.js error page with a stack trace on every route in the file — including
// requests that should simply have been rejected as unauthorised.
let client: SupabaseClient | null = null;

function getAdminClient(): SupabaseClient {
  if (client) return client;
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set to use the API");
  }
  client = createClient(url, key);
  return client;
}

/** Proxy so route handlers can keep importing `supabaseAdmin` as a value. */
export const supabaseAdmin = new Proxy({} as SupabaseClient, {
  get(_target, prop) {
    return Reflect.get(getAdminClient(), prop);
  },
});

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
      const resolved = await resolveApiKey(getAdminClient(), token);
      return resolved ? { ownerId: resolved.ownerId, via: "key" } : null;
    }

    const { data, error } = await getAdminClient().auth.getUser(token);
    if (error || !data.user) return null;
    return { ownerId: data.user.id, via: "session" };
  } catch {
    return null;
  }
}

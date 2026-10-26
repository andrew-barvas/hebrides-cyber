// Shared caller resolution for the public REST API (/api/v1/*).
//
// Accepts two credential types against the same routes:
//   - an API key   (Authorization: Bearer hc_live_…) — CI, scripts, the Action
//   - a session JWT (Authorization: Bearer <supabase jwt>) — the dashboard
//
// Both resolve to the same { ownerId } so route handlers never branch on how
// the caller authenticated.
//
// An API key with an IP allowlist only authenticates from those addresses.
// From anywhere else it gets null — the same 401 as an unknown key — so a
// leaked key doesn't confirm to whoever holds it that it's real. The refusal
// is recorded on the key (last_blocked_ip/at) for its owner to see instead.
// Session JWTs are never IP-restricted: the allowlist is a property of a key.
import type { NextApiRequest } from "next";
import { API_SCOPES, type ApiScope } from "./apiScopes";
import { looksLikeApiKey, recordBlockedApiKeyUse, resolveApiKey } from "./apiKeys";
import { isIpAllowed } from "./ipAllowlist";
import { getClientIp } from "./rateLimit";
import { getSupabaseAdmin, supabaseAdmin } from "./supabaseAdmin";

export { supabaseAdmin };

export type ApiCaller = {
  ownerId: string;
  /** How the caller authenticated — used to gate key management to sessions. */
  via: "key" | "session";
  /** Present for a key; absent for a session, which is unscoped. See apiScopes.ts. */
  scopes?: ApiScope[];
};

function isV1Request(req: NextApiRequest): boolean {
  return (req.url ?? "").split("?")[0].startsWith("/api/v1/");
}

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
      if (!resolved) return null;
      if (resolved.allowedCidrs.length > 0) {
        const ip = getClientIp(req);
        if (!isIpAllowed(ip, resolved.allowedCidrs)) {
          await recordBlockedApiKeyUse(getSupabaseAdmin(), resolved.keyId, ip);
          return null;
        }
      }
      // Scoping is only enforced per-route on /api/v1. Every other route that
      // accepts a key predates scopes, so a key narrowed below full access is
      // refused there outright (same 401 as an unknown key) rather than
      // silently gaining whatever those routes allow.
      const isFullAccess = API_SCOPES.every((s) => resolved.scopes.includes(s));
      if (!isFullAccess && !isV1Request(req)) return null;
      return { ownerId: resolved.ownerId, via: "key", scopes: resolved.scopes };
    }

    const { data, error } = await getSupabaseAdmin().auth.getUser(token);
    if (error || !data.user) return null;
    return { ownerId: data.user.id, via: "session" };
  } catch {
    return null;
  }
}

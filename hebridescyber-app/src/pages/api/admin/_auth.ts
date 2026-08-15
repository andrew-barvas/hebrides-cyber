// Shared admin-auth helper — every admin API route calls this before
// touching any data. Validates the caller's bearer token, then checks
// is_admin on the users table via the service role (bypasses RLS).
import { createClient } from "@supabase/supabase-js";
import type { NextApiRequest } from "next";

export const supabaseAdmin = createClient(
  process.env.SUPABASE_URL ?? "",
  process.env.SUPABASE_SERVICE_ROLE_KEY ?? ""
);

/**
 * Returns the caller's user ID if they are a valid, authenticated admin.
 * Returns null otherwise — callers must return 401/403 themselves.
 */
export async function requireAdmin(req: NextApiRequest): Promise<string | null> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) return null;
  const token = authHeader.slice("Bearer ".length);
  const { data, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !data.user) return null;
  const { data: profile } = await supabaseAdmin
    .from("users")
    .select("is_admin")
    .eq("id", data.user.id)
    .maybeSingle();
  return profile?.is_admin ? data.user.id : null;
}

export function methodNotAllowed(allowed: string[]) {
  return { status: 405, headers: { Allow: allowed.join(", ") } };
}

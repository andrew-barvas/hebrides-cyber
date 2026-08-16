import type { NextApiRequest } from "next";
import { supabaseAdmin } from "./supabaseAdmin";

export { supabaseAdmin };

export async function requireAdmin(req: NextApiRequest): Promise<string | null> {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) return null;
  const token = authHeader.slice("Bearer ".length);
  // A missing SUPABASE_URL/SERVICE_ROLE_KEY now throws inside supabaseAdmin's
  // lazy getter rather than at import — catch it here so that surfaces as
  // "not an admin" (null) instead of an unhandled 500 in every admin route.
  try {
    const { data, error } = await supabaseAdmin.auth.getUser(token);
    if (error || !data.user) return null;
    const { data: profile } = await supabaseAdmin
      .from("users")
      .select("is_admin")
      .eq("id", data.user.id)
      .maybeSingle();
    return profile?.is_admin ? data.user.id : null;
  } catch {
    return null;
  }
}

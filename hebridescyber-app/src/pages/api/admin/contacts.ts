import type { NextApiRequest, NextApiResponse } from "next";
import { createClient } from "@supabase/supabase-js";
import { supabaseAdmin } from "@/lib/supabaseAdmin";

async function isAdmin(req: NextApiRequest): Promise<boolean> {
  const authHeader = req.headers.authorization ?? "";
  const token = authHeader.replace(/^Bearer\s+/i, "");
  if (!token) return false;

  // Failure here (missing env vars, an unreachable Supabase, a malformed
  // token) means "not an admin", never an unhandled 500 — the caller only
  // ever sees a clean 403.
  try {
    // Verify the JWT and look up is_admin using the service-role client.
    const anonClient = createClient(
      process.env.SUPABASE_URL ?? "",
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? ""
    );
    const { data: { user } } = await anonClient.auth.getUser(token);
    if (!user) return false;

    const { data } = await supabaseAdmin
      .from("users")
      .select("is_admin")
      .eq("id", user.id)
      .maybeSingle();
    return data?.is_admin === true;
  } catch {
    return false;
  }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (!(await isAdmin(req))) return res.status(403).json({ error: "Forbidden" });

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin
      .from("contact_enquiries")
      .select("id, name, email, url, message, read, created_at")
      .order("created_at", { ascending: false })
      .limit(100);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data);
  }

  if (req.method === "PATCH") {
    const { id, read } = req.body as { id: string; read: boolean };
    if (!id) return res.status(400).json({ error: "Missing id" });
    const { error } = await supabaseAdmin
      .from("contact_enquiries")
      .update({ read })
      .eq("id", id);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: "Method not allowed" });
}

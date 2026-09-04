import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // E-08 (docs/ENHANCEMENTS.md): previously built its own anon
  // createClient() here to verify the caller's JWT, a second, different
  // implementation of the same check @/lib/adminAuth's requireAdmin()
  // already does (that one uses the service-role client directly) — two
  // implementations of the same security control drifting apart is exactly
  // how the is_admin RLS gap this session's migration 017 fixed nearly went
  // unnoticed a second way.
  if (!(await requireAdmin(req))) return res.status(403).json({ error: "Forbidden" });

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

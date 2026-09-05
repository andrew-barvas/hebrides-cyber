import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { parseBody } from "@/lib/validate";

const patchSchema = z.object({ id: z.string().min(1), read: z.boolean() });

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
    // E-17 (docs/ENHANCEMENTS.md): used to be a flat .limit(100) with no way
    // to see anything past it. Paginated the same way admin/audit.ts already
    // does correctly.
    const page = Math.max(1, parseInt(typeof req.query.page === "string" ? req.query.page : "1", 10));
    const pageSize = 25;
    const offset = (page - 1) * pageSize;

    const { data, error, count } = await supabaseAdmin
      .from("contact_enquiries")
      .select("id, name, email, url, message, company, team_size, budget_range, read, created_at", { count: "exact" })
      .order("created_at", { ascending: false })
      .range(offset, offset + pageSize - 1);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ enquiries: data ?? [], total: count ?? 0, page, pageSize });
  }

  if (req.method === "PATCH") {
    const body = parseBody(patchSchema, req.body, res);
    if (!body) return;
    const { id, read } = body;
    const { error } = await supabaseAdmin
      .from("contact_enquiries")
      .update({ read })
      .eq("id", id);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: "Method not allowed" });
}

import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  const page = Math.max(1, parseInt(typeof req.query.page === "string" ? req.query.page : "1", 10));
  const pageSize = 50;
  const offset = (page - 1) * pageSize;
  const search = typeof req.query.search === "string" ? req.query.search.trim() : "";
  const actor = typeof req.query.actor === "string" ? req.query.actor.trim() : "";

  let query = supabaseAdmin
    .from("audit_logs")
    .select("id, actor_email, action, resource_type, resource_id, metadata, created_at", { count: "exact" })
    .order("created_at", { ascending: false })
    .range(offset, offset + pageSize - 1);

  if (search) query = query.ilike("action", `%${search}%`);
  if (actor) query = query.ilike("actor_email", `%${actor}%`);

  const { data, error, count } = await query;
  if (error) return res.status(500).json({ error: error.message });

  return res.status(200).json({ logs: data ?? [], total: count ?? 0, page, pageSize });
}

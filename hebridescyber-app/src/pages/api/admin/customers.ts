import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  const search = typeof req.query.search === "string" ? req.query.search.trim() : "";
  const page = Math.max(1, parseInt(typeof req.query.page === "string" ? req.query.page : "1", 10));
  const pageSize = 25;
  const offset = (page - 1) * pageSize;

  let usersQ = supabaseAdmin
    .from("users")
    .select("id, email, company_name, is_admin, created_at", { count: "exact" })
    .order("created_at", { ascending: false })
    .range(offset, offset + pageSize - 1);

  if (search) {
    usersQ = usersQ.or(`email.ilike.%${search}%,company_name.ilike.%${search}%`);
  }

  const { data: users, error, count } = await usersQ;
  if (error) return res.status(500).json({ error: error.message });

  const userIds = (users ?? []).map((u) => u.id);

  const [{ data: subs }, { data: scanCounts }] = await Promise.all([
    supabaseAdmin.from("subscriptions").select("owner, plan, status, source, grant_reason").in("owner", userIds),
    supabaseAdmin.from("scans").select("owner").in("owner", userIds),
  ]);

  const subMap = new Map((subs ?? []).map((s) => [s.owner, s]));
  const scanMap = new Map<string, number>();
  for (const s of scanCounts ?? []) {
    scanMap.set(s.owner, (scanMap.get(s.owner) ?? 0) + 1);
  }

  const customers = (users ?? []).map((u) => {
    const sub = subMap.get(u.id);
    return {
      id: u.id,
      email: u.email,
      company_name: u.company_name ?? null,
      is_admin: u.is_admin ?? false,
      plan: sub?.plan ?? null,
      subscription_status: sub?.status ?? null,
      plan_source: sub?.source ?? null,
      grant_reason: sub?.grant_reason ?? null,
      scan_count: scanMap.get(u.id) ?? 0,
      created_at: u.created_at,
    };
  });

  return res.status(200).json({ customers, total: count ?? 0, page, pageSize });
}

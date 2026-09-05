import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";

// Service-role-backed admin API — deliberately NOT just a client-side
// Supabase query, because RLS on `users`/`subscriptions`/`scans` only lets
// people see their own rows (correctly). An admin view needs to see
// everyone's, which means going through a server-side check of the
// caller's own `is_admin` flag before using the service role key to
// bypass RLS. Never do this bypass client-side.

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).end("Method Not Allowed");
  }

  // E-08 (docs/ENHANCEMENTS.md): previously hand-rolled this exact check
  // inline (a fresh auth.getUser() + users.is_admin lookup) instead of
  // calling the shared requireAdmin() — two implementations of the same
  // security control drifting apart is exactly how the is_admin RLS gap
  // this session's migration 017 fixed nearly went unnoticed a second way.
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  // E-17 (docs/ENHANCEMENTS.md): this used to fetch every users/subscriptions/
  // scans row with no .range()/.limit() and count scans in JS — silently
  // wrong totals once past PostgREST's default 1000-row ceiling, a
  // correctness bug at scale, not just a performance one. Paginated the
  // customer list the same way admin/customers.ts already does correctly;
  // the two aggregate totals below now come from exact-count head queries
  // instead of array .length, so they stay right regardless of page size.
  const page = Math.max(1, parseInt(typeof req.query.page === "string" ? req.query.page : "1", 10));
  const pageSize = 25;
  const offset = (page - 1) * pageSize;

  const {
    data: profiles,
    error: profilesError,
    count: customerCount,
  } = await supabaseAdmin
    .from("users")
    .select("id, email, company_name, is_admin, created_at", { count: "exact" })
    .order("created_at", { ascending: false })
    .range(offset, offset + pageSize - 1);
  if (profilesError) return res.status(500).json({ error: profilesError.message });

  const userIds = (profiles ?? []).map((p) => p.id);

  const [{ data: subscriptions }, { data: pageScans }, { count: totalScans }, { count: activeSubscriptions }] = await Promise.all([
    supabaseAdmin.from("subscriptions").select("owner, plan, status").in("owner", userIds),
    supabaseAdmin.from("scans").select("owner").in("owner", userIds),
    supabaseAdmin.from("scans").select("id", { count: "exact", head: true }),
    supabaseAdmin.from("subscriptions").select("owner", { count: "exact", head: true }).eq("status", "active"),
  ]);

  const subsByOwner = new Map((subscriptions ?? []).map((s) => [s.owner, s]));
  const scanCounts = new Map<string, number>();
  for (const scan of pageScans ?? []) {
    scanCounts.set(scan.owner, (scanCounts.get(scan.owner) ?? 0) + 1);
  }

  const customers = (profiles ?? []).map((p) => {
    const sub = subsByOwner.get(p.id);
    return {
      id: p.id,
      email: p.email,
      companyName: p.company_name,
      isAdmin: p.is_admin,
      plan: sub?.status === "active" ? sub.plan : "none",
      subscriptionStatus: sub?.status ?? null,
      scanCount: scanCounts.get(p.id) ?? 0,
      createdAt: p.created_at,
    };
  });

  return res.status(200).json({
    customers,
    page,
    pageSize,
    totals: {
      customers: customerCount ?? 0,
      activeSubscriptions: activeSubscriptions ?? 0,
      totalScans: totalScans ?? 0,
    },
  });
}

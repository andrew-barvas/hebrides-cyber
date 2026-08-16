import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/supabaseAdmin";

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

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing Authorization Bearer token" });
  }

  // supabaseAdmin is constructed lazily on first property access — a missing
  // SUPABASE_URL/SERVICE_ROLE_KEY throws here rather than at import, so it's
  // caught and returned as a clean 401 instead of an unhandled 500.
  try {
    const { data: callerData, error: callerError } = await supabaseAdmin.auth.getUser(
      authHeader.slice("Bearer ".length)
    );
    if (callerError || !callerData.user) {
      return res.status(401).json({ error: "Invalid session" });
    }

    const { data: callerProfile } = await supabaseAdmin
      .from("users")
      .select("is_admin")
      .eq("id", callerData.user.id)
      .maybeSingle();

    if (!callerProfile?.is_admin) {
      return res.status(403).json({ error: "Admin access required" });
    }
  } catch {
    return res.status(401).json({ error: "Invalid session" });
  }

  // TODO: this is three round-trips merged in JS rather than one SQL join
  // (via an RPC/view) — fine at seed-data scale, revisit if the customer
  // list grows past a page or two.
  const [{ data: profiles }, { data: subscriptions }, { data: scans }] = await Promise.all([
    supabaseAdmin.from("users").select("id, email, company_name, is_admin, created_at").order("created_at", { ascending: false }),
    supabaseAdmin.from("subscriptions").select("owner, plan, status"),
    supabaseAdmin.from("scans").select("id, owner"),
  ]);

  const subsByOwner = new Map((subscriptions ?? []).map((s) => [s.owner, s]));
  const scanCounts = new Map<string, number>();
  for (const scan of scans ?? []) {
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
    totals: {
      customers: customers.length,
      activeSubscriptions: customers.filter((c) => c.subscriptionStatus === "active").length,
      totalScans: scans?.length ?? 0,
    },
  });
}

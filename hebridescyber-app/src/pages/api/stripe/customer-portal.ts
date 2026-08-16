import type { NextApiRequest, NextApiResponse } from "next";
import { getStripe } from "@/lib/stripeClient";
import { supabaseAdmin } from "@/lib/supabaseAdmin";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).end();
  }

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing Authorization Bearer token" });
  }

  let customerId: string;
  try {
    // supabaseAdmin's client is constructed lazily on first access — a
    // missing SUPABASE_URL/SERVICE_ROLE_KEY throws here rather than at
    // import, so it's caught below instead of an unhandled 500.
    const { data: userData, error: authError } = await supabaseAdmin.auth.getUser(
      authHeader.slice("Bearer ".length)
    );
    if (authError || !userData.user) {
      return res.status(401).json({ error: "Invalid session" });
    }

    // Look up the Stripe customer ID from the subscriptions table.
    const { data: sub } = await supabaseAdmin
      .from("subscriptions")
      .select("stripe_customer_id")
      .eq("owner", userData.user.id)
      .maybeSingle();

    if (!sub?.stripe_customer_id) {
      return res.status(404).json({ error: "No active subscription found. Subscribe first from the pricing page." });
    }
    customerId = sub.stripe_customer_id;
  } catch {
    return res.status(401).json({ error: "Invalid session" });
  }

  const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000";

  try {
    const portalSession = await getStripe().billingPortal.sessions.create({
      customer: customerId,
      return_url: `${siteUrl}/dashboard`,
    });
    return res.status(200).json({ url: portalSession.url });
  } catch (err) {
    console.error("[customer-portal] Stripe error:", err);
    return res.status(502).json({ error: (err as Error).message });
  }
}

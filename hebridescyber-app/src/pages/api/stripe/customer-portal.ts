import type { NextApiRequest, NextApiResponse } from "next";
import Stripe from "stripe";
import { createClient } from "@supabase/supabase-js";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "sk_test_placeholder", {
  apiVersion: "2024-06-20",
});
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL ?? "",
  process.env.SUPABASE_SERVICE_ROLE_KEY ?? ""
);

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).end();
  }

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing Authorization Bearer token" });
  }

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

  const customerId = sub?.stripe_customer_id;
  if (!customerId) {
    return res.status(404).json({ error: "No active subscription found. Subscribe first from the pricing page." });
  }

  const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000";

  try {
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: `${siteUrl}/dashboard`,
    });
    return res.status(200).json({ url: portalSession.url });
  } catch (err) {
    console.error("[customer-portal] Stripe error:", err);
    return res.status(502).json({ error: (err as Error).message });
  }
}

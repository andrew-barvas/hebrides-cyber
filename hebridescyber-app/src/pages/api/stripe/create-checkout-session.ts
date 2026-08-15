import type { NextApiRequest, NextApiResponse } from "next";
import Stripe from "stripe";
import { createClient } from "@supabase/supabase-js";

// Creates a real Stripe Checkout Session for one of the three
// subscription plans. Called by src/app/pricing/page.tsx. The webhook
// (webhook.ts) is what actually activates the subscription once Stripe
// confirms payment — this endpoint only starts the flow.
//
// TODO: STRIPE_PRICE_BASIC/PRO/AGENCY must be real Price IDs from the
// Stripe Dashboard (Products > select product > copy the price's API ID,
// looks like "price_1AbC..."). This will 500 until they're set.

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "sk_test_placeholder", { apiVersion: "2024-06-20" });
const supabaseAdmin = createClient(process.env.SUPABASE_URL ?? "", process.env.SUPABASE_SERVICE_ROLE_KEY ?? "");

const PRICE_IDS: Record<"basic" | "pro" | "agency", string | undefined> = {
  basic: process.env.STRIPE_PRICE_BASIC,
  pro: process.env.STRIPE_PRICE_PRO,
  agency: process.env.STRIPE_PRICE_AGENCY,
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).end("Method Not Allowed");
  }

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing Authorization Bearer token" });
  }
  const { data: userData, error: authError } = await supabaseAdmin.auth.getUser(authHeader.slice("Bearer ".length));
  if (authError || !userData.user) {
    return res.status(401).json({ error: "Invalid session" });
  }

  const plan = req.body?.plan as "basic" | "pro" | "agency" | undefined;
  const priceId = plan ? PRICE_IDS[plan] : undefined;
  if (!plan || !priceId) {
    return res.status(400).json({
      error: `Unknown or unconfigured plan "${plan}" — set STRIPE_PRICE_${(plan ?? "").toUpperCase()} in the Function/API environment.`,
    });
  }

  const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000";

  try {
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      // Ties the Checkout Session back to the Supabase user — the webhook
      // reads this to know whose `subscriptions` row to upsert.
      client_reference_id: userData.user.id,
      customer_email: userData.user.email,
      metadata: { plan },
      success_url: `${siteUrl}/dashboard?checkout=success`,
      cancel_url: `${siteUrl}/pricing?checkout=cancelled`,
    });

    return res.status(200).json({ url: session.url });
  } catch (err) {
    console.error("[create-checkout-session] Stripe error:", err);
    return res.status(502).json({ error: (err as Error).message });
  }
}

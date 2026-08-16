import type { NextApiRequest, NextApiResponse } from "next";
import { getStripe } from "@/lib/stripeClient";
import { supabaseAdmin } from "@/lib/supabaseAdmin";

// Creates a real Stripe Checkout Session for one of the three
// subscription plans. Called by src/app/pricing/page.tsx. The webhook
// (webhook.ts) is what actually activates the subscription once Stripe
// confirms payment — this endpoint only starts the flow.
//
// TODO: STRIPE_PRICE_BASIC/PRO/AGENCY must be real Price IDs from the
// Stripe Dashboard (Products > select product > copy the price's API ID,
// looks like "price_1AbC..."). This will 500 until they're set.

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

  let userData: Awaited<ReturnType<typeof supabaseAdmin.auth.getUser>>["data"];
  try {
    // Both supabaseAdmin and getStripe() construct lazily — a missing env var
    // throws here rather than at import, so it's caught below instead of
    // crashing with an unhandled 500.
    const result = await supabaseAdmin.auth.getUser(authHeader.slice("Bearer ".length));
    if (result.error || !result.data.user) return res.status(401).json({ error: "Invalid session" });
    userData = result.data;
  } catch {
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
    const session = await getStripe().checkout.sessions.create({
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

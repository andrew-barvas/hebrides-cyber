import type { NextApiRequest, NextApiResponse } from "next";
import { getStripe } from "@/lib/stripeClient";
import { supabaseAdmin } from "@/lib/supabaseAdmin";
import { isSubscriptionPlan, type SubscriptionPlan } from "@/lib/planAccess";

// Creates a real Stripe Checkout Session for one of the subscription plans.
// Called by src/app/pricing/page.tsx and src/app/services/page.tsx. The
// webhook (webhook.ts) is what actually activates the subscription once
// Stripe confirms payment — this endpoint only starts the flow.
//
// STRIPE_PRICE_* must be real Price IDs from the Stripe Dashboard (Products >
// select product > copy the price's API ID, looks like "price_1AbC..."). Until
// they (and STRIPE_SECRET_KEY) are set, a customer gets a 503
// `checkout_unavailable` with words they can act on; which variable is
// missing goes to the server log, never to the browser.
//
// The scanner plans bill monthly only. The Lookout managed exposure review
// plans (docs/DEFENSIVE-ASSESSMENT-PLAN.md, "Pricing & Tiers") also bill
// quarterly and annually, one Stripe price per period. A missing price for
// the chosen plan and period is a 503, never another plan's or period's price.

const CHECKOUT_UNAVAILABLE = {
  error: "Online sign-up for this plan isn't open yet. Contact us and we'll set your account up.",
  code: "checkout_unavailable",
};

const BILLING_PERIODS = ["monthly", "quarterly", "annual"] as const;
type BillingPeriod = (typeof BILLING_PERIODS)[number];

type PriceEnv = { env: string; id: string | undefined };
const price = (env: string): PriceEnv => ({ env, id: process.env[env] });

const PRICE_IDS: Record<SubscriptionPlan, Partial<Record<BillingPeriod, PriceEnv>>> = {
  basic: { monthly: price("STRIPE_PRICE_BASIC") },
  pro: { monthly: price("STRIPE_PRICE_PRO") },
  agency: { monthly: price("STRIPE_PRICE_AGENCY") },
  tier_a: { monthly: price("STRIPE_PRICE_TIER_A") },
  lookout_essentials: {
    monthly: price("STRIPE_PRICE_LOOKOUT_ESSENTIALS_MONTHLY"),
    quarterly: price("STRIPE_PRICE_LOOKOUT_ESSENTIALS_QUARTERLY"),
    annual: price("STRIPE_PRICE_LOOKOUT_ESSENTIALS_ANNUAL"),
  },
  lookout_assured: {
    monthly: price("STRIPE_PRICE_LOOKOUT_ASSURED_MONTHLY"),
    quarterly: price("STRIPE_PRICE_LOOKOUT_ASSURED_QUARTERLY"),
    annual: price("STRIPE_PRICE_LOOKOUT_ASSURED_ANNUAL"),
  },
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

  const plan = req.body?.plan as unknown;
  if (!isSubscriptionPlan(plan)) {
    return res.status(400).json({ error: "Unknown plan." });
  }
  // Only a missing period means monthly; null or any other value is a 400.
  const rawPeriod = (req.body?.period === undefined ? "monthly" : req.body.period) as unknown;
  const period = (BILLING_PERIODS as readonly unknown[]).includes(rawPeriod) ? (rawPeriod as BillingPeriod) : undefined;
  const priceEnv = period ? PRICE_IDS[plan][period] : undefined;
  if (!period || !priceEnv) {
    return res.status(400).json({ error: "That billing period isn't available for this plan." });
  }
  const priceId = priceEnv.id;
  if (!priceId) {
    console.error(`[create-checkout-session] ${priceEnv.env} is not set; checkout for "${plan}" (${period}) is unavailable.`);
    return res.status(503).json(CHECKOUT_UNAVAILABLE);
  }

  const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";

  try {
    const session = await getStripe().checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      // Ties the Checkout Session back to the Supabase user — the webhook
      // reads this to know whose `subscriptions` row to upsert.
      client_reference_id: userData.user.id,
      customer_email: userData.user.email,
      metadata: { plan, period },
      // Also stamped onto the Subscription object itself (not just this
      // Checkout Session) — webhook.ts's customer.subscription.updated
      // handler reads sub.metadata.plan, and without this it was always
      // undefined, silently falling back to "basic" on every renewal,
      // proration, or billing-portal plan change for Pro/Agency customers.
      subscription_data: { metadata: { plan, period } },
      success_url: `${siteUrl}/dashboard?checkout=success`,
      cancel_url: `${siteUrl}/pricing?checkout=cancelled`,
    });

    return res.status(200).json({ url: session.url });
  } catch (err) {
    console.error("[create-checkout-session] Stripe error:", err);
    if (/STRIPE_SECRET_KEY/.test((err as Error).message)) return res.status(503).json(CHECKOUT_UNAVAILABLE);
    return res.status(502).json({ error: "We couldn't start checkout. Please try again, or contact us if it keeps happening." });
  }
}

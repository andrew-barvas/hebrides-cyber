import type { NextApiRequest, NextApiResponse } from "next";
import type Stripe from "stripe";
import { buffer } from "node:stream/consumers";
import { getStripe } from "@/lib/stripeClient";
import { supabaseAdmin } from "@/lib/supabaseAdmin";

export const config = {
  api: { bodyParser: false },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function isAlreadyProcessed(eventId: string): Promise<boolean> {
  // Every downstream write in this handler is an upsert/update keyed on a
  // stable id, so processing an event twice is harmless — but silently
  // dropping one isn't. If this check itself fails (including supabaseAdmin's
  // lazy client failing to construct), fail open: treat it as unprocessed and
  // let the handler run rather than crashing this request unhandled.
  try {
    const { data } = await supabaseAdmin
      .from("audit_logs")
      .select("id")
      .eq("resource_id", eventId)
      .eq("resource_type", "stripe_event")
      .maybeSingle();
    return !!data;
  } catch (err) {
    console.error("[stripe webhook] idempotency check failed, proceeding anyway:", err);
    return false;
  }
}

async function markProcessed(
  eventId: string,
  action: string,
  extra?: { actor?: string | null; actorEmail?: string | null; metadata?: Record<string, unknown> }
) {
  await supabaseAdmin.from("audit_logs").insert({
    action,
    resource_type: "stripe_event",
    resource_id: eventId,
    actor: extra?.actor ?? null,
    // admin/audit.ts's search UI filters on actor_email — populate it here
    // too (from the caller's already-fetched profile, where available)
    // rather than leaving Stripe-originated entries unsearchable by that
    // filter while everything else in the log is.
    actor_email: extra?.actorEmail ?? null,
    metadata: extra?.metadata ?? null,
  });
}

/**
 * subscription.updated/payment_failed/subscription.deleted only carry a
 * stripe_subscription_id, not the owner directly — this resolves both owner
 * and email in one query so those audit_logs entries stay attributable
 * (checkout.completed gets this for free, already has `owner` in scope).
 */
async function lookupSubscriptionOwner(stripeSubscriptionId: string): Promise<{ owner: string | null; email: string | null }> {
  const { data: sub } = await supabaseAdmin
    .from("subscriptions")
    .select("owner")
    .eq("stripe_subscription_id", stripeSubscriptionId)
    .maybeSingle();
  if (!sub?.owner) return { owner: null, email: null };

  // Two queries, not an embed: subscriptions.owner references auth.users,
  // not public.users, so there's no FK path for PostgREST to follow a
  // subscriptions.select("owner, users(email)")-style embed through.
  const { data: profile } = await supabaseAdmin.from("users").select("email").eq("id", sub.owner).maybeSingle();
  return { owner: sub.owner, email: profile?.email ?? null };
}

async function sendWelcomeEmail(email: string, plan: string) {
  const key = process.env.SENDGRID_API_KEY;
  if (!key) return;
  const from = process.env.SENDGRID_FROM_EMAIL ?? "hello@hebridescyber.co.uk";
  // Was hardcoded to hebridescyber.com (never-registered domain) instead of
  // reading NEXT_PUBLIC_SITE_URL like every other outbound-link site in this
  // codebase does — fixed alongside the real hebridescyber.co.uk domain going
  // live.
  const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
  await fetch("https://api.sendgrid.com/v3/mail/send", {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      personalizations: [{ to: [{ email }] }],
      from: { email: from, name: "Hebrides Cyber" },
      subject: `Welcome to Hebrides Cyber — ${plan.charAt(0).toUpperCase() + plan.slice(1)} Plan`,
      content: [
        {
          type: "text/plain",
          value: `Hi,

Thanks for subscribing to the Hebrides Cyber ${plan} plan.

Your first automated security scan will run within the next 24 hours. You'll receive a Security Score report by email once it's complete.

In the meantime, you can:
- Add sites to monitor: ${siteUrl}/dashboard
- View your scan history: ${siteUrl}/dashboard/scans
- Manage your billing: ${siteUrl}/dashboard (click "Manage billing")

If you have any questions, just reply to this email.

— Andrew & the Hebrides Cyber team`,
        },
      ],
    }),
  }).catch((err) => console.error("[webhook] welcome email failed:", err.message));
}

// ─── Handler ──────────────────────────────────────────────────────────────────

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).end();
  }

  const sig = req.headers["stripe-signature"];
  const rawBody = await buffer(req);

  let event: Stripe.Event;
  try {
    if (!sig || !process.env.STRIPE_WEBHOOK_SECRET) {
      throw new Error("Missing Stripe signature or webhook secret");
    }
    event = getStripe().webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("[stripe webhook] signature verification failed:", err);
    return res.status(400).send(`Webhook Error: ${(err as Error).message}`);
  }

  // Idempotency guard — skip already-processed events.
  if (await isAlreadyProcessed(event.id)) {
    return res.status(200).json({ received: true, skipped: true });
  }

  try {
    switch (event.type) {

      case "checkout.session.completed": {
        const session = event.data.object as Stripe.Checkout.Session;
        const owner = session.client_reference_id;
        const plan = (session.metadata?.plan as "basic" | "pro" | "agency") ?? "basic";
        if (!owner) break;

        let currentPeriodEnd: string | null = null;
        let stripeSubscriptionId: string | null = null;
        if (typeof session.subscription === "string") {
          stripeSubscriptionId = session.subscription;
          const sub = await getStripe().subscriptions.retrieve(session.subscription);
          currentPeriodEnd = new Date(sub.current_period_end * 1000).toISOString();
        }

        const stripeCustomerId = typeof session.customer === "string" ? session.customer : null;

        await supabaseAdmin.from("subscriptions").upsert(
          {
            owner,
            stripe_customer_id: stripeCustomerId,
            stripe_subscription_id: stripeSubscriptionId,
            plan,
            status: "active",
            current_period_end: currentPeriodEnd,
            updated_at: new Date().toISOString(),
          },
          { onConflict: "owner" }
        );

        // Mirror stripe_customer_id onto users table for portal lookups.
        if (stripeCustomerId) {
          await supabaseAdmin
            .from("users")
            .update({ stripe_customer_id: stripeCustomerId })
            .eq("id", owner);
        }

        // Send welcome email (once per user — flag prevents duplicates on retry).
        const { data: profile } = await supabaseAdmin
          .from("users")
          .select("email, onboarding_email_sent")
          .eq("id", owner)
          .maybeSingle();

        if (profile && !profile.onboarding_email_sent) {
          await sendWelcomeEmail(profile.email, plan);
          await supabaseAdmin
            .from("users")
            .update({ onboarding_email_sent: true })
            .eq("id", owner);
        }

        await markProcessed(event.id, "stripe.checkout.completed", { actor: owner, metadata: { plan } });
        break;
      }

      case "customer.subscription.updated": {
        const sub = event.data.object as Stripe.Subscription;
        const plan = (sub.metadata?.plan as "basic" | "pro" | "agency" | undefined) ?? "basic";
        const status = sub.status === "active" ? "active"
          : sub.status === "past_due" ? "past_due"
          : sub.status === "canceled" ? "cancelled"
          : "inactive";

        await supabaseAdmin
          .from("subscriptions")
          .update({
            plan,
            status,
            current_period_end: new Date(sub.current_period_end * 1000).toISOString(),
            updated_at: new Date().toISOString(),
          })
          .eq("stripe_subscription_id", sub.id);

        {
          const { owner, email } = await lookupSubscriptionOwner(sub.id);
          await markProcessed(event.id, "stripe.subscription.updated", {
            actor: owner,
            actorEmail: email,
            metadata: { plan, status },
          });
        }
        break;
      }

      case "invoice.payment_failed": {
        const invoice = event.data.object as Stripe.Invoice;
        const subId = typeof invoice.subscription === "string" ? invoice.subscription : null;
        if (!subId) break;

        await supabaseAdmin
          .from("subscriptions")
          .update({ status: "past_due", updated_at: new Date().toISOString() })
          .eq("stripe_subscription_id", subId);

        {
          const { owner, email } = await lookupSubscriptionOwner(subId);
          await markProcessed(event.id, "stripe.payment_failed", { actor: owner, actorEmail: email });
        }
        break;
      }

      case "customer.subscription.deleted": {
        const sub = event.data.object as Stripe.Subscription;
        await supabaseAdmin
          .from("subscriptions")
          .update({ status: "cancelled", updated_at: new Date().toISOString() })
          .eq("stripe_subscription_id", sub.id);

        {
          const { owner, email } = await lookupSubscriptionOwner(sub.id);
          await markProcessed(event.id, "stripe.subscription.deleted", { actor: owner, actorEmail: email });
        }
        break;
      }

      default:
        console.log(`[stripe webhook] unhandled event type: ${event.type}`);
    }
  } catch (err) {
    console.error("[stripe webhook] handler error:", err);
    return res.status(500).json({ error: "Internal error processing webhook" });
  }

  return res.status(200).json({ received: true });
}

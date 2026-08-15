import type { NextApiRequest, NextApiResponse } from "next";
import Stripe from "stripe";
import { buffer } from "node:stream/consumers";
import { createClient } from "@supabase/supabase-js";

export const config = {
  api: { bodyParser: false },
};

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY ?? "sk_test_placeholder", {
  apiVersion: "2024-06-20",
});

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL ?? "",
  process.env.SUPABASE_SERVICE_ROLE_KEY ?? ""
);

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function isAlreadyProcessed(eventId: string): Promise<boolean> {
  const { data } = await supabaseAdmin
    .from("audit_logs")
    .select("id")
    .eq("resource_id", eventId)
    .eq("resource_type", "stripe_event")
    .maybeSingle();
  return !!data;
}

async function markProcessed(eventId: string, action: string) {
  await supabaseAdmin.from("audit_logs").insert({
    action,
    resource_type: "stripe_event",
    resource_id: eventId,
  });
}

async function sendWelcomeEmail(email: string, plan: string) {
  const key = process.env.SENDGRID_API_KEY;
  if (!key) return;
  const from = process.env.SENDGRID_FROM_EMAIL ?? "hello@hebridescyber.com";
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
- Add sites to monitor: https://hebridescyber.com/dashboard
- View your scan history: https://hebridescyber.com/dashboard/scans
- Manage your billing: https://hebridescyber.com/dashboard (click "Manage billing")

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
    event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);
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
          const sub = await stripe.subscriptions.retrieve(session.subscription);
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

        await markProcessed(event.id, "stripe.checkout.completed");
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

        await markProcessed(event.id, "stripe.subscription.updated");
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

        await markProcessed(event.id, "stripe.payment_failed");
        break;
      }

      case "customer.subscription.deleted": {
        const sub = event.data.object as Stripe.Subscription;
        await supabaseAdmin
          .from("subscriptions")
          .update({ status: "cancelled", updated_at: new Date().toISOString() })
          .eq("stripe_subscription_id", sub.id);

        await markProcessed(event.id, "stripe.subscription.deleted");
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

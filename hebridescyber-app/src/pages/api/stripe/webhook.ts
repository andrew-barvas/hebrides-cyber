import type { NextApiRequest, NextApiResponse } from "next";
import Stripe from "stripe";
import { buffer } from "node:stream/consumers";
import { createClient } from "@supabase/supabase-js";

// Stripe webhook handler (Pages Router API route — coexists fine with the
// App Router pages elsewhere in src/app).
//
// Expects the Checkout Session to have been created with:
//   - client_reference_id: the Supabase auth user id (so we know who to
//     attach the subscription to)
//   - metadata.plan: one of "basic" | "pro" | "agency"
// TODO: wire that up in the pricing page checkout call — currently there
// is no Checkout Session creation endpoint in this scaffold, only the
// webhook consumer side. See src/app/pricing/page.tsx TODO.
//
// TODO before production:
// - Verify this route is deployed somewhere that supports the Node runtime
//   with raw body access (Azure Static Web Apps "managed functions" or a
//   separate Azure Function both work; static export does NOT).
// - Add retry/idempotency handling keyed on event.id (e.g. an
//   `audit_logs` row per processed event.id, skip if already present).
// - Handle proration / plan-change events (customer.subscription.updated).

export const config = {
  api: {
    bodyParser: false, // Stripe requires the raw body to verify the signature.
  },
};

const stripeSecretKey = process.env.STRIPE_SECRET_KEY ?? "";
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET ?? "";

const stripe = new Stripe(stripeSecretKey || "sk_test_placeholder", {
  apiVersion: "2024-06-20",
});

// Service-role client — this webhook is the ONLY place besides run-scan
// that should be writing to the subscriptions table with elevated
// privileges. Never expose SUPABASE_SERVICE_ROLE_KEY to the browser.
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL ?? "",
  process.env.SUPABASE_SERVICE_ROLE_KEY ?? ""
);

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).end("Method Not Allowed");
  }

  const sig = req.headers["stripe-signature"];
  const rawBody = await buffer(req);

  let event: Stripe.Event;
  try {
    if (!sig || !webhookSecret) {
      throw new Error("Missing Stripe signature or webhook secret");
    }
    event = stripe.webhooks.constructEvent(rawBody, sig, webhookSecret);
  } catch (err) {
    console.error("[stripe webhook] signature verification failed:", err);
    return res.status(400).send(`Webhook Error: ${(err as Error).message}`);
  }

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object as Stripe.Checkout.Session;
        const owner = session.client_reference_id;
        const plan = (session.metadata?.plan as "basic" | "pro" | "agency" | undefined) ?? "basic";

        if (!owner) {
          console.error("[stripe webhook] checkout.session.completed with no client_reference_id — cannot attach subscription");
          break;
        }

        // Retrieve the subscription to get its current period end.
        let currentPeriodEnd: string | null = null;
        let stripeSubscriptionId: string | null = null;
        if (typeof session.subscription === "string") {
          stripeSubscriptionId = session.subscription;
          const sub = await stripe.subscriptions.retrieve(session.subscription);
          currentPeriodEnd = new Date(sub.current_period_end * 1000).toISOString();
        }

        const { error: upsertError } = await supabaseAdmin.from("subscriptions").upsert(
          {
            owner,
            stripe_customer_id: typeof session.customer === "string" ? session.customer : null,
            stripe_subscription_id: stripeSubscriptionId,
            plan,
            status: "active",
            updated_at: new Date().toISOString(),
            // TODO: add a current_period_end column to the subscriptions
            // table (sql/migrations/002_*.sql) if you want to store this —
            // currently only tracked here for reference, not persisted.
          },
          { onConflict: "owner" }
        );

        if (upsertError) {
          console.error("[stripe webhook] failed to upsert subscription:", upsertError.message);
        } else {
          console.log(`[stripe webhook] activated ${plan} subscription for owner ${owner}`, { currentPeriodEnd });
        }
        break;
      }

      case "invoice.payment_failed": {
        const invoice = event.data.object as Stripe.Invoice;
        const stripeSubscriptionId = typeof invoice.subscription === "string" ? invoice.subscription : null;

        if (!stripeSubscriptionId) {
          console.error("[stripe webhook] invoice.payment_failed with no subscription id");
          break;
        }

        const { error: updateError } = await supabaseAdmin
          .from("subscriptions")
          .update({ status: "past_due", updated_at: new Date().toISOString() })
          .eq("stripe_subscription_id", stripeSubscriptionId);

        if (updateError) {
          console.error("[stripe webhook] failed to mark subscription past_due:", updateError.message);
        } else {
          console.log(`[stripe webhook] marked subscription ${stripeSubscriptionId} as past_due`);
        }
        break;
      }

      case "customer.subscription.deleted": {
        const subscription = event.data.object as Stripe.Subscription;
        const { error: cancelError } = await supabaseAdmin
          .from("subscriptions")
          .update({ status: "cancelled", updated_at: new Date().toISOString() })
          .eq("stripe_subscription_id", subscription.id);

        if (cancelError) {
          console.error("[stripe webhook] failed to mark subscription cancelled:", cancelError.message);
        }
        break;
      }

      default:
        console.log(`[stripe webhook] unhandled event type: ${event.type}`);
    }
  } catch (err) {
    // Log and still return 200 where possible per Stripe's guidance, but
    // a hard failure here should alert someone — TODO: wire up error
    // reporting (Sentry/Application Insights) rather than just console.error.
    console.error("[stripe webhook] handler error:", err);
    return res.status(500).json({ error: "Internal error processing webhook" });
  }

  res.status(200).json({ received: true });
}

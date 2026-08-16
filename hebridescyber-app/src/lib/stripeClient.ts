// Canonical Stripe client for API routes.
//
// Unlike @supabase/supabase-js, the Stripe SDK doesn't throw on construction —
// each route was falling back to a placeholder key ("sk_test_placeholder")
// and only failing later, when Stripe's API rejects it with a generic "Invalid
// API Key provided" error. Centralising this means one clear error message
// ("Stripe is not configured") instead of that cryptic one repeated per file,
// and one place to bump the API version.
import Stripe from "stripe";

let client: Stripe | null = null;

export function getStripe(): Stripe {
  if (client) return client;
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) {
    throw new Error("STRIPE_SECRET_KEY must be set");
  }
  client = new Stripe(key, { apiVersion: "2024-06-20" });
  return client;
}

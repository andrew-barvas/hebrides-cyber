"use client";

// Plan cards and Stripe checkout for Lookout, the managed exposure review
// (docs/DEFENSIVE-ASSESSMENT-PLAN.md, "Pricing & Tiers"; copy from
// marketing/17-lookout-managed-exposure-review.md). Built to be mounted on
// the Lookout product page (/lookout, which a separate change adds) in place
// of its "Book a call" buttons.
// Same flow as /pricing: POST /api/stripe/create-checkout-session with the
// plan and billing period, then hand the browser to Stripe. Until the owner
// has created the six Lookout prices (OT-34) that route answers 503
// `checkout_unavailable`, shown here with a contact link.

import { useState } from "react";
import Link from "next/link";
import { getSession } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { SegmentedControl } from "@/components/ui/segmented-control";

type Period = "monthly" | "quarterly" | "annual";
type LookoutPlan = "lookout_essentials" | "lookout_assured";

const PERIODS: readonly { value: Period; label: string }[] = [
  { value: "monthly", label: "Monthly" },
  { value: "quarterly", label: "Quarterly" },
  { value: "annual", label: "Annual" },
];

export const LOOKOUT_PLANS: readonly {
  id: LookoutPlan;
  name: string;
  prices: Record<Period, string>;
  features: string[];
}[] = [
  {
    id: "lookout_essentials",
    name: "Essentials",
    prices: { monthly: "£149 / month", quarterly: "£399 / quarter", annual: "£1,490 / year" },
    features: [
      "Daily automated checks of your verified domains",
      "Engineer-written report every quarter",
      "One 30-minute review call each quarter",
      "Fixes confirmed at the next report",
    ],
  },
  {
    id: "lookout_assured",
    name: "Assured",
    prices: { monthly: "£299 / month", quarterly: "£799 / quarter", annual: "£2,990 / year" },
    features: [
      "Daily automated checks of your verified domains",
      "Engineer-written report every month",
      "Two review calls each quarter",
      "Fixes confirmed within the month, from the next scheduled check",
      "Help answering the external-exposure questions in Cyber Essentials and insurance questionnaires",
    ],
  },
];

class CheckoutError extends Error {
  constructor(message: string, readonly code?: string) {
    super(message);
  }
}

export default function LookoutCheckout() {
  const [period, setPeriod] = useState<Period>("monthly");
  const [loadingPlan, setLoadingPlan] = useState<LookoutPlan | null>(null);
  const [error, setError] = useState<{ message: string; code?: string } | null>(null);

  async function subscribe(plan: LookoutPlan) {
    setError(null);
    setLoadingPlan(plan);
    try {
      const session = await getSession();
      if (!session) {
        setError({ message: "Sign in first, then come back to start Lookout." });
        return;
      }
      const res = await fetch("/api/stripe/create-checkout-session", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.access_token}` },
        body: JSON.stringify({ plan, period }),
      });
      const body = await res.json();
      if (!res.ok) throw new CheckoutError(body.error ?? `Checkout failed (${res.status})`, body.code);
      // eslint-disable-next-line react-hooks/immutability
      window.location.href = body.url;
    } catch (err) {
      setError({ message: (err as Error).message, code: err instanceof CheckoutError ? err.code : undefined });
    } finally {
      setLoadingPlan(null);
    }
  }

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-cybermuted">Billed monthly, quarterly or annually.</p>
        <SegmentedControl aria-label="Billing period" value={period} onChange={setPeriod} options={PERIODS} />
      </div>

      {error && (
        <p role="alert" className="mb-4 text-sm text-danger">
          {error.message}
          {error.code === "checkout_unavailable" && (
            <>
              {" "}
              <Link href="/contact" className="font-semibold text-neon hover:underline">
                Contact us
              </Link>
            </>
          )}
        </p>
      )}

      <div className="grid gap-4 sm:grid-cols-2">
        {LOOKOUT_PLANS.map((p) => (
          <div key={p.id} className="flex flex-col rounded-lg border border-cyberborder bg-cyberpanel p-5">
            <h3 className="font-mono text-sm font-semibold text-neon">Lookout {p.name}</h3>
            <p className="my-3 font-mono text-2xl font-bold text-cybertext">{p.prices[period]}</p>
            <ul className="flex-1 space-y-1.5">
              {p.features.map((f) => (
                <li key={f} className="flex items-start gap-2 text-xs text-cybertext/70">
                  <span className="mt-0.5 shrink-0 text-neon/50">›</span>
                  <span>{f}</span>
                </li>
              ))}
            </ul>
            <Button className="mt-5 w-full" onClick={() => subscribe(p.id)} disabled={loadingPlan !== null}>
              {loadingPlan === p.id ? "Starting checkout…" : `Start Lookout ${p.name}`}
            </Button>
          </div>
        ))}
      </div>

      <p className="mt-4 text-xs text-cybermuted">
        Each plan includes a fixed amount of engineer time; larger estates are quoted separately. Paying by
        invoice, or need extra domains, an IP range or a custom scope?{" "}
        <Link href="/contact" className="text-neon underline underline-offset-2 hover:text-cybertext">
          Enquire
        </Link>
        .
      </p>
    </div>
  );
}

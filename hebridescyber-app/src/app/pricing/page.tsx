"use client";

// Pricing copy sourced from marketing/03-pricing-page.md.
// Subscription buttons call /api/stripe/create-checkout-session (real
// Stripe Checkout) — see that file's TODO about setting real Price IDs.
// One-off audit "buttons" stay as a mailto/contact link since those are
// scoped, invoiced engagements, not self-serve subscriptions.

import { Suspense, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { getSession } from "@/lib/auth";

class CheckoutError extends Error {
  constructor(message: string, readonly code?: string) {
    super(message);
  }
}

// Stripe sends a customer who backs out of checkout to /pricing?checkout=cancelled.
// Read in its own component, under Suspense, so the page still renders statically.
function CheckoutCancelledNotice() {
  const params = useSearchParams();
  if (params?.get("checkout") !== "cancelled") return null;
  return (
    <p role="status" className="mb-5 text-sm text-cybertext/70">
      Checkout cancelled, so nothing was charged. Pick a plan whenever you&apos;re ready.
    </p>
  );
}

const oneOff = [
  { name: "Small Website Audit", price: "£300", desc: "Automated scan, headers & TLS checks, dependency scan, 1-page Security Score." },
  { name: "Standard Web App Audit", price: "£800", desc: "OWASP Top 10 manual testing, API testing, auth/session checks, 8–12 page report." },
  { name: "Full SaaS Audit", price: "£1,800", desc: "Full manual pen test, CI/CD review, cloud permissions review, 20+ page report." },
];

// Tier A is deliberately not sold here (SPRINT-PLAN H6: hidden). Every
// feature it would add (strix, cairn, credential spraying) is `not_configured`,
// and there is no customer path to the offensive profile; owner decision
// 2026-10-23: "leave not_configured, do not market". The plan still exists
// for accounts that already have it, and checkout still accepts "tier_a".
const subscriptions: Array<{
  id: "basic" | "pro" | "agency";
  name: string;
  price: string;
  tagline: string;
  features: string[];
  highlight?: boolean;
}> = [
  {
    id: "basic",
    name: "Basic",
    price: "£20/mo",
    tagline: "Continuous monitoring for a single site.",
    features: [
      "1 monitored site",
      "Weekly automated scans",
      "Monthly Security Score email",
      "Critical-finding alerts",
    ],
  },
  {
    id: "pro",
    name: "Pro",
    price: "£35/mo",
    tagline: "Everything in Basic, plus faster scans and integrations.",
    features: [
      "Up to 3 monitored sites",
      "Daily automated scans",
      "Dependency & CI/CD scanning",
      "Slack & Microsoft Teams alerts",
      "Uptime alerts via your UptimeRobot account",
    ],
    highlight: true,
  },
  {
    id: "agency",
    name: "Agency",
    price: "£75/mo",
    tagline: "Everything in Pro, plus team & client-facing tools.",
    features: [
      "Up to 15 monitored sites",
      "Team collaboration & roles",
      "White-label PDF reports",
      "Authenticated (logged-in) scanning",
      "Priority support",
    ],
  },
];

export default function PricingPage() {
  const [loadingPlan, setLoadingPlan] = useState<string | null>(null);
  const [error, setError] = useState<{ message: string; code?: string } | null>(null);

  async function subscribe(plan: "basic" | "pro" | "agency") {
    setError(null);
    setLoadingPlan(plan);
    try {
      const session = await getSession();
      if (!session) {
        setError({ message: "Sign in first, then come back to subscribe." });
        return;
      }
      const res = await fetch("/api/stripe/create-checkout-session", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.access_token}` },
        body: JSON.stringify({ plan }),
      });
      const body = await res.json();
      if (!res.ok) throw new CheckoutError(body.error ?? `Checkout failed (${res.status})`, body.code);
      // react-hooks/immutability treats window.location as a value being
      // mutated; assigning href is just a navigation to Stripe Checkout.
      // eslint-disable-next-line react-hooks/immutability
      window.location.href = body.url;
    } catch (err) {
      setError({ message: (err as Error).message, code: err instanceof CheckoutError ? err.code : undefined });
    } finally {
      setLoadingPlan(null);
    }
  }

  return (
    <div className="bg-cyberbg min-h-screen">
      {/* Hero */}
      <section className="relative overflow-hidden bg-cyberbg px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-60" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> pricing.list()
          </p>
          <h1 className="text-4xl font-bold text-cybertext">Pricing</h1>
          <p className="mx-auto mt-4 max-w-xl text-cybertext/70">
            Transparent pricing for predictable security. Choose a one-off audit
            or a monthly plan for continuous protection.
          </p>
        </div>
      </section>

      <div className="mx-auto max-w-5xl px-6 pb-20 pt-12">
        {/* One-off audits */}
        <h2 className="mb-6 font-mono text-xs uppercase tracking-widest text-cybertext/70">
          One-off audits
        </h2>
        <div className="mb-14 grid gap-5 sm:grid-cols-3">
          {oneOff.map((p) => (
            <div
              key={p.name}
              className="flex flex-col rounded-xl border border-cyberborder bg-cyberpanel p-6"
            >
              <h3 className="text-base font-semibold text-cybertext">{p.name}</h3>
              <p className="my-3 font-mono text-3xl font-bold text-neon">{p.price}</p>
              <p className="flex-1 text-sm text-cybertext/60">{p.desc}</p>
              <Link
                href="/contact"
                className="mt-5 rounded-md border border-neon px-4 py-2 text-center text-sm font-semibold text-neon hover:bg-neon hover:text-cyberbg transition-colors"
              >
                Enquire
              </Link>
            </div>
          ))}
        </div>

        {/* Monthly subscriptions */}
        <h2 className="mb-6 font-mono text-xs uppercase tracking-widest text-cybertext/70">
          Monthly subscriptions — Security Score
        </h2>
        <Suspense fallback={null}>
          <CheckoutCancelledNotice />
        </Suspense>
        {error && (
          <p role="alert" className="mb-5 text-sm text-red-400">
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
        <div className="grid gap-5 sm:grid-cols-3">
          {subscriptions.map((p) => (
            <div
              key={p.id}
              className={`flex flex-col rounded-xl border p-6 ${
                p.highlight
                  ? "border-neon bg-cyberpanel shadow-glow"
                  : "border-cyberborder bg-cyberpanel"
              }`}
            >
              {p.highlight && (
                <span className="mb-3 self-start rounded-full border border-neon px-2 py-0.5 font-mono text-[10px] text-neon">
                  Most popular
                </span>
              )}
              <h3 className="text-base font-semibold text-cybertext">{p.name}</h3>
              <p className="my-3 font-mono text-3xl font-bold text-neon">{p.price}</p>
              <p className="mb-3 text-sm text-cybertext/60">{p.tagline}</p>
              <ul className="flex-1 space-y-2 text-sm text-cybertext/80">
                {p.features.map((f) => (
                  <li key={f} className="flex items-start gap-2">
                    <span className="mt-0.5 text-neon" aria-hidden="true">✓</span>
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
              <button
                onClick={() => subscribe(p.id)}
                disabled={loadingPlan === p.id}
                className={`mt-5 rounded-md px-4 py-2 text-sm font-semibold transition-opacity disabled:opacity-50 ${
                  p.highlight
                    ? "bg-neon text-cyberbg shadow-glow hover:opacity-90"
                    : "border border-neon text-neon hover:bg-neon hover:text-cyberbg transition-colors"
                }`}
              >
                {loadingPlan === p.id ? "Redirecting…" : "Get started"}
              </button>
            </div>
          ))}
        </div>

        <p className="mt-4 text-xs text-cybertext/50">
          By subscribing you agree to our{" "}
          <Link href="/terms" className="text-neon hover:underline">
            Terms of Service
          </Link>{" "}
          and{" "}
          <Link href="/privacy" className="text-neon hover:underline">
            Privacy Policy
          </Link>
          .
        </p>

        <p className="mt-6 font-mono text-xs text-cybertext/60">
          Not signed in?{" "}
          <Link href="/login" className="text-neon hover:underline">
            Sign in
          </Link>{" "}
          or{" "}
          <Link href="/signup" className="text-neon hover:underline">
            create an account
          </Link>
          , then come back to subscribe.
        </p>
      </div>
    </div>
  );
}

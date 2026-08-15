"use client";

// Pricing copy sourced from marketing/03-pricing-page.md.
// Subscription buttons call /api/stripe/create-checkout-session (real
// Stripe Checkout) — see that file's TODO about setting real Price IDs.
// One-off audit "buttons" stay as a mailto/contact link since those are
// scoped, invoiced engagements, not self-serve subscriptions.

import { useState } from "react";
import Link from "next/link";
import { getSession } from "@/lib/auth";

const oneOff = [
  { name: "Small Website Audit", price: "£300", desc: "Automated scan, headers & TLS checks, dependency scan, 1-page Security Score." },
  { name: "Standard Web App Audit", price: "£800", desc: "OWASP Top 10 manual testing, API testing, auth/session checks, 8–12 page report." },
  { name: "Full SaaS Audit", price: "£1,800", desc: "Full manual pen test, CI/CD review, cloud permissions review, 20+ page report." },
];

const subscriptions: Array<{ id: "basic" | "pro" | "agency"; name: string; price: string; desc: string; highlight?: boolean }> = [
  { id: "basic", name: "Basic", price: "£20/mo", desc: "Weekly automated scans, monthly Security Score email, critical alerts." },
  { id: "pro", name: "Pro", price: "£35/mo", desc: "Everything in Basic + dependency monitoring, Slack alerts, quarterly manual review.", highlight: true },
  { id: "agency", name: "Agency", price: "£75/mo", desc: "Multi-site monitoring, white-label PDF reports, priority support." },
];

export default function PricingPage() {
  const [loadingPlan, setLoadingPlan] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function subscribe(plan: "basic" | "pro" | "agency") {
    setError(null);
    setLoadingPlan(plan);
    try {
      const session = await getSession();
      if (!session) {
        setError("Sign in first, then come back to subscribe.");
        return;
      }
      const res = await fetch("/api/stripe/create-checkout-session", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.access_token}` },
        body: JSON.stringify({ plan }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? `Checkout failed (${res.status})`);
      window.location.href = body.url;
    } catch (err) {
      setError((err as Error).message);
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
          <p className="mb-3 font-mono text-sm text-neon">
            <span className="text-slatelight/40">$</span> pricing.list()
          </p>
          <h1 className="text-4xl font-bold text-white">Pricing</h1>
          <p className="mx-auto mt-4 max-w-xl text-slatelight/70">
            Transparent pricing for predictable security. Choose a one-off audit
            or a monthly plan for continuous protection.
          </p>
        </div>
      </section>

      <div className="mx-auto max-w-5xl px-6 pb-20 pt-12">
        {/* One-off audits */}
        <h2 className="mb-6 font-mono text-xs uppercase tracking-widest text-slatelight/50">
          // one-off audits
        </h2>
        <div className="mb-14 grid gap-5 sm:grid-cols-3">
          {oneOff.map((p) => (
            <div
              key={p.name}
              className="flex flex-col rounded-xl border border-cyberborder bg-cyberpanel p-6"
            >
              <h3 className="text-base font-semibold text-white">{p.name}</h3>
              <p className="my-3 font-mono text-3xl font-bold text-neon">{p.price}</p>
              <p className="flex-1 text-sm text-slatelight/60">{p.desc}</p>
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
        <h2 className="mb-6 font-mono text-xs uppercase tracking-widest text-slatelight/50">
          // monthly subscriptions — security score
        </h2>
        {error && <p className="mb-5 text-sm text-red-400">{error}</p>}
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
              <h3 className="text-base font-semibold text-white">{p.name}</h3>
              <p className="my-3 font-mono text-3xl font-bold text-neon">{p.price}</p>
              <p className="flex-1 text-sm text-slatelight/60">{p.desc}</p>
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

        <p className="mt-6 font-mono text-xs text-slatelight/40">
          // not signed in?{" "}
          <Link href="/login" className="text-neon hover:underline">
            sign in
          </Link>{" "}
          first, then come back to subscribe.
        </p>
      </div>
    </div>
  );
}

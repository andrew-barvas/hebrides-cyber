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

const subscriptions: Array<{ id: "basic" | "pro" | "agency"; name: string; price: string; desc: string }> = [
  { id: "basic", name: "Basic", price: "£20/mo", desc: "Weekly automated scans, monthly Security Score email, critical alerts." },
  { id: "pro", name: "Pro", price: "£35/mo", desc: "Everything in Basic + dependency monitoring, Slack alerts, quarterly manual review." },
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
    <div className="mx-auto max-w-5xl px-6 py-16">
      <p className="mb-1 font-mono text-xs text-atlantic/60">// pricing.list()</p>
      <h1 className="mb-2 text-3xl font-bold text-atlantic">Pricing</h1>
      <p className="mb-10 text-slatedark/80">
        Transparent pricing for predictable security. Choose a one-off audit
        or a monthly plan for continuous protection.
      </p>

      <h2 className="mb-4 text-xl font-semibold">One-off Audits</h2>
      <div className="mb-12 grid gap-6 sm:grid-cols-3">
        {oneOff.map((p) => (
          <div key={p.name} className="flex flex-col rounded-lg border border-slate-200 p-6">
            <h3 className="text-lg font-semibold">{p.name}</h3>
            <p className="my-2 text-2xl font-bold text-atlantic">{p.price}</p>
            <p className="flex-1 text-sm text-slatedark/80">{p.desc}</p>
            <Link
              href="/contact"
              className="mt-4 rounded-md bg-atlantic px-4 py-2 text-center text-sm font-semibold text-white hover:opacity-90"
            >
              Enquire
            </Link>
          </div>
        ))}
      </div>

      <h2 className="mb-4 text-xl font-semibold">
        Monthly Subscriptions (Security Score)
      </h2>
      {error && <p className="mb-4 text-sm text-red-600">{error}</p>}
      <div className="grid gap-6 sm:grid-cols-3">
        {subscriptions.map((p) => (
          <div key={p.id} className="flex flex-col rounded-lg border border-slate-200 p-6">
            <h3 className="text-lg font-semibold">{p.name}</h3>
            <p className="my-2 text-2xl font-bold text-atlantic">{p.price}</p>
            <p className="flex-1 text-sm text-slatedark/80">{p.desc}</p>
            <button
              onClick={() => subscribe(p.id)}
              disabled={loadingPlan === p.id}
              className="mt-4 rounded-md bg-seafoam px-4 py-2 text-sm font-semibold text-slatedark hover:opacity-90 disabled:opacity-50"
            >
              {loadingPlan === p.id ? "Redirecting…" : "Get started"}
            </button>
          </div>
        ))}
      </div>
      <p className="mt-4 text-xs text-slatedark/60">
        Not signed in yet?{" "}
        <Link href="/dashboard" className="underline">
          Sign in from the dashboard
        </Link>{" "}
        first, then come back to subscribe.
      </p>
    </div>
  );
}

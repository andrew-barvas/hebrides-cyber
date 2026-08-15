"use client";

import Link from "next/link";

export type Plan = "none" | "basic" | "pro" | "agency";

// Bespoke "what's next" card per plan tier — the dashboard's upsell path.
// Deliberately always suggests the *next* tier up (or a one-off add-on for
// the top tier) rather than a generic "upgrade now" banner, since a
// concrete next step converts better than a vague one.
const COPY: Record<Plan, { label: string; message: string; cta: string; href: string }> = {
  none: {
    label: "No active plan",
    message: "You're on ad-hoc scans only. Subscribe to Basic for weekly automated monitoring and alerts.",
    cta: "View plans",
    href: "/pricing",
  },
  basic: {
    label: "Basic plan",
    message: "Upgrade to Pro for dependency monitoring, Slack alerts, and a quarterly manual review.",
    cta: "Upgrade to Pro",
    href: "/pricing",
  },
  pro: {
    label: "Pro plan",
    message: "Managing more than one site? Agency adds multi-site monitoring and white-label PDF reports.",
    cta: "Upgrade to Agency",
    href: "/pricing",
  },
  agency: {
    label: "Agency plan",
    message: "You're on our top tier. Need deeper assurance? Ask about a manual penetration test or an incident response retainer.",
    cta: "Enquire",
    href: "/contact",
  },
};

export default function PlanUpsell({ plan }: { plan: Plan }) {
  const copy = COPY[plan];
  return (
    <div className="mb-8 flex items-center justify-between rounded-lg border border-seafoam/40 bg-seafoam/10 p-4">
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-atlantic/70">{copy.label}</p>
        <p className="mt-1 text-sm text-slatedark/80">{copy.message}</p>
      </div>
      <Link
        href={copy.href}
        className="ml-4 shrink-0 rounded-md bg-atlantic px-4 py-2 text-sm font-semibold text-white hover:opacity-90"
      >
        {copy.cta}
      </Link>
    </div>
  );
}

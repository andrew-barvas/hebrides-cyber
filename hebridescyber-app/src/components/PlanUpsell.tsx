"use client";

import Link from "next/link";

export type Plan = "none" | "basic" | "pro" | "agency" | "tier_a";

const COPY: Record<Plan, { label: string; message: string; cta: string; href: string }> = {
  none: {
    label: "No active plan",
    message: "You're on ad-hoc scans only. Subscribe to Basic for weekly automated monitoring and alerts.",
    cta: "View plans",
    href: "/pricing",
  },
  basic: {
    label: "Basic plan",
    message: "Upgrade to Pro for dependency monitoring and Slack alerts.",
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
    message: "Need deeper assurance? Tier A adds opt-in offensive readiness testing on sites you authorise.",
    cta: "See Tier A",
    href: "/pricing",
  },
  tier_a: {
    label: "Tier A plan",
    message: "You're on our top tier. Need deeper assurance? Ask about a manual penetration test or an incident response retainer.",
    cta: "Enquire",
    href: "/contact",
  },
};

export default function PlanUpsell({ plan }: { plan: Plan }) {
  const copy = COPY[plan];
  return (
    <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-neon/20 bg-neon/5 p-4">
      <div>
        <p className="font-mono text-xs font-semibold uppercase tracking-wide text-neon/60">{copy.label}</p>
        <p className="mt-1 text-sm text-cybertext/70">{copy.message}</p>
      </div>
      <Link
        href={copy.href}
        className="shrink-0 rounded-md bg-neon px-4 py-2 text-sm font-semibold text-cyberbg hover:opacity-90 shadow-glowsm transition-opacity"
      >
        {copy.cta}
      </Link>
    </div>
  );
}

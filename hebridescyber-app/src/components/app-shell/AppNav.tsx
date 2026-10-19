"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { CircleUser, LayoutDashboard, ListChecks, Plug, Plus, ScanSearch, Server, ShieldCheck, Timer, TrendingUp, type LucideIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import type { Plan } from "@/components/PlanUpsell";

type NavItem = { href: string; label: string; icon: LucideIcon };

export const NAV_ITEMS: readonly NavItem[] = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { href: "/dashboard/scans", label: "Scans", icon: ScanSearch },
  { href: "/dashboard/scans/history", label: "Trends", icon: TrendingUp },
  { href: "/dashboard/findings", label: "Findings", icon: ListChecks },
  { href: "/dashboard/assets", label: "Assets", icon: Server },
  { href: "/dashboard/sla", label: "SLAs", icon: Timer },
  { href: "/dashboard/cyber-essentials", label: "Cyber Essentials", icon: ShieldCheck },
  { href: "/dashboard/integrations", label: "Integrations", icon: Plug },
  { href: "/account", label: "Account", icon: CircleUser },
];

/** The nav href that owns `pathname`: the longest item href that is the path
 *  itself or a segment-prefix of it. Longest-wins is what keeps
 *  /dashboard/scans/history on Trends (not Scans) and /dashboard/scans/abc on
 *  Scans (not Overview). */
export function activeNavHref(pathname: string): string | null {
  let best: string | null = null;
  for (const { href } of NAV_ITEMS) {
    const owns = pathname === href || pathname.startsWith(`${href}/`);
    if (owns && (!best || href.length > best.length)) best = href;
  }
  return best;
}

const PLAN_NAMES: Record<Plan, string> = { none: "Free", basic: "Basic", pro: "Pro", agency: "Agency" };

type PlanSummary = { plan: Plan; billingPlan: Plan; planStatus: string | null } | null;

function PlanBadge({ summary }: { summary: PlanSummary }) {
  if (!summary) return <Skeleton className="h-[4.5rem] w-full rounded-lg" />;

  if (summary.planStatus === "past_due") {
    return (
      <div className="rounded-lg border border-danger/30 bg-danger/10 p-3 text-xs">
        <p className="font-semibold text-danger">Payment failed</p>
        <p className="mt-0.5 text-cybermuted">{PLAN_NAMES[summary.billingPlan]} features are paused.</p>
        <Link href="/account" className="mt-2 inline-block font-medium text-neon hover:underline">
          Update billing →
        </Link>
      </div>
    );
  }

  const free = summary.plan === "none";
  return (
    <div className="rounded-lg border border-cyberborder p-3 text-xs">
      <p className="font-mono uppercase tracking-wider text-cybermuted">Plan</p>
      <p className="mt-0.5 text-sm font-semibold text-cybertext">{PLAN_NAMES[summary.plan]}</p>
      <Link href={free ? "/pricing" : "/account"} className="mt-2 inline-block font-medium text-neon hover:underline">
        {free ? "Upgrade →" : "Manage →"}
      </Link>
    </div>
  );
}

export function AppSidebar({ summary, className }: { summary: PlanSummary; className?: string }) {
  const active = activeNavHref(usePathname() ?? "");
  return (
    <aside className={cn("w-52 shrink-0", className)}>
      <div className="sticky top-6 space-y-6">
        <Button asChild className="w-full">
          <Link href="/dashboard/scans#run-a-scan">
            <Plus aria-hidden="true" />
            New scan
          </Link>
        </Button>
        <nav aria-label="Dashboard">
          <ul className="space-y-1">
            {NAV_ITEMS.map(({ href, label, icon: Icon }) => (
              <li key={href}>
                <Link
                  href={href}
                  aria-current={href === active ? "page" : undefined}
                  className={cn(
                    "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                    href === active ? "bg-neon/10 text-neon" : "text-cybermuted hover:bg-cyberborder/50 hover:text-cybertext"
                  )}
                >
                  <Icon className="size-4 shrink-0" aria-hidden="true" />
                  {label}
                </Link>
              </li>
            ))}
          </ul>
        </nav>
        <PlanBadge summary={summary} />
      </div>
    </aside>
  );
}

/** Below lg: a horizontally scrolling row instead of a second hamburger — the
 *  global Header already owns one, and two stacked menus is a known trap. */
export function AppMobileNav({ className }: { className?: string }) {
  const active = activeNavHref(usePathname() ?? "");
  return (
    <nav aria-label="Dashboard" className={cn("-mx-4 overflow-x-auto px-4 sm:-mx-6 sm:px-6", className)}>
      <ul className="flex gap-2 pb-1">
        {NAV_ITEMS.map(({ href, label, icon: Icon }) => (
          <li key={href} className="shrink-0">
            <Link
              href={href}
              aria-current={href === active ? "page" : undefined}
              className={cn(
                "flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm font-medium transition-colors",
                href === active
                  ? "border-neon/50 bg-neon/10 text-neon"
                  : "border-cyberborder text-cybermuted hover:text-cybertext"
              )}
            >
              <Icon className="size-4 shrink-0" aria-hidden="true" />
              {label}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}

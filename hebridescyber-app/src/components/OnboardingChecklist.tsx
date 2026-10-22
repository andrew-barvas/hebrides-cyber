"use client";

// E-16 (docs/ENHANCEMENTS.md): a dashboard checklist for a new signup —
// verify domain -> run first scan -> read the report -> set an alert
// channel — rather than relying on documentation nobody reads post-signup
// (see docs/ONBOARDING.md §0's reasoning for why that doc is
// contributor-only, not customer-facing; this is the real customer-facing
// onboarding surface).
//
// Every step is derived from data the dashboard already has or cheaply
// fetches (verifications/webhooks rows) — no separate "has the user seen
// this" tracking table. "Read the report" specifically uses "does a
// completed scan with a report exist" as its completion signal, not real
// view tracking; a good-enough proxy given the report is the very next
// thing on the page once a scan completes; see dashboard/page.tsx's
// overviewScan.
//
// Manual dismissal is a per-viewer localStorage preference (matches the
// leaderboard rank-change baseline precedent elsewhere in this app) —
// wrapped in try/catch since a private window or blocked site data throws
// rather than silently no-opping.

import { useState } from "react";
import Link from "next/link";

const DISMISS_KEY = "onboarding-checklist-dismissed";

function readDismissed(): boolean {
  try {
    return localStorage.getItem(DISMISS_KEY) === "1";
  } catch {
    return false;
  }
}

function writeDismissed() {
  try {
    localStorage.setItem(DISMISS_KEY, "1");
  } catch {
    // Ignore — worst case the checklist reappears next visit.
  }
}

export type OnboardingStep = {
  key: string;
  label: string;
  done: boolean;
  href?: string;
  actionLabel?: string;
};

type Props = {
  verifiedDomain: boolean;
  hasScanned: boolean;
  hasReport: boolean;
  hasAlertChannel: boolean;
  /** Pro/Agency get "connect Slack or Teams"; every other plan (including
   *  none/free) gets pointed at the always-available outbound webhook
   *  instead, since Slack/Teams alerts are plan-gated (dashboard/page.tsx)
   *  but outbound webhooks deliberately aren't (USER-GUIDE.md §3.5). */
  alertChannelIsSlackTeams: boolean;
};

export default function OnboardingChecklist({
  verifiedDomain,
  hasScanned,
  hasReport,
  hasAlertChannel,
  alertChannelIsSlackTeams,
}: Props) {
  const [dismissed, setDismissed] = useState(readDismissed);

  // Each step deep-links to the dashboard section that completes it — these
  // were same-page anchors ("…below") when the dashboard was one long page.
  const steps: OnboardingStep[] = [
    {
      key: "verify",
      label: "Verify a domain you own",
      done: verifiedDomain,
      href: "/dashboard/assets#domain-verification",
      actionLabel: "Verify a domain",
    },
    {
      key: "scan",
      label: "Run your first scan",
      done: hasScanned,
      href: "/dashboard/scans#run-a-scan",
      actionLabel: "Run a scan",
    },
    {
      key: "report",
      label: "Read your first report",
      done: hasReport,
      href: "/dashboard/scans#scan-history",
      actionLabel: "View scans",
    },
    {
      key: "alert",
      label: alertChannelIsSlackTeams ? "Connect Slack or Teams for alerts" : "Set up a webhook for alerts",
      done: hasAlertChannel,
      href: "/dashboard/integrations#alerts",
      actionLabel: "Set up alerts",
    },
  ];

  const allDone = steps.every((s) => s.done);
  if (allDone || dismissed) return null;

  const completedCount = steps.filter((s) => s.done).length;

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="font-mono text-xs text-cybermuted uppercase tracking-wide">
          // getting started ({completedCount}/{steps.length})
        </h2>
        <button
          onClick={() => {
            writeDismissed();
            setDismissed(true);
          }}
          className="text-xs text-cybermuted hover:text-cybertext/70 transition-colors"
        >
          Dismiss
        </button>
      </div>
      <ul className="flex flex-col gap-2">
        {steps.map((step) => (
          <li key={step.key} className="flex items-center justify-between text-sm">
            <span className={step.done ? "text-neon" : "text-cybertext/70"}>
              {step.done ? "✓ " : "○ "}
              {step.label}
            </span>
            {!step.done && step.href && (
              <Link href={step.href} className="text-xs text-neon hover:underline">
                {step.actionLabel}
              </Link>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

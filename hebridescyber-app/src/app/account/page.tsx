"use client";

// Account — who you are, what you pay for, who's on your team, how you sign
// in. Everything that connects Hebrides Cyber to another system (API keys,
// webhooks, repo, API spec, Jira/Linear, on-call) lives under
// /dashboard/integrations now.

import { useEffect, useState } from "react";
import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";
import { useBillingPortal } from "@/lib/useBillingPortal";
import { planIncludes } from "@/lib/planAccess";
import { useAppSession } from "@/components/app-shell/AppShell";
import RequestAudit from "@/components/RequestAudit";
import TeamSection from "@/components/TeamSection";
import TwoFactor from "@/components/TwoFactor";
import BrandingSection from "@/components/BrandingSection";
import AccountDeletion from "@/components/AccountDeletion";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";

const PLAN_LABELS: Record<string, string> = {
  none: "No plan",
  basic: "Basic",
  pro: "Pro",
  agency: "Agency",
  tier_a: "Tier A",
};

export default function AccountPage() {
  const { email, userId, accessToken, plan, billingPlan, planStatus } = useAppSession();
  const billing = useBillingPortal();
  const [branding, setBranding] = useState<{ logoUrl: string | null; name: string | null } | null>(null);
  // Gated on the active plan, as branding-logo.ts is: a lapsed Agency
  // account would otherwise get a form whose saves are refused.
  const brandingEnabled = planIncludes(plan, "agency");

  // White-label branding is Agency and up, and not part of the shared session.
  useEffect(() => {
    if (!brandingEnabled) return;
    supabase
      .from("subscriptions")
      .select("brand_logo_url, brand_name")
      .maybeSingle()
      .then(({ data }) =>
        setBranding({
          logoUrl: (data?.brand_logo_url as string | null) ?? null,
          name: (data?.brand_name as string | null) ?? null,
        })
      );
  }, [brandingEnabled]);

  return (
    <div className="space-y-8">
      <PageHeader eyebrow="$ ./account" title="Account" description="Profile, billing, team and sign-in security." />

      <Alert variant="info" title="Looking for API keys, webhooks or integrations?">
        They now live together under{" "}
        <Link href="/dashboard/integrations" className="font-medium text-neon hover:underline">
          Integrations
        </Link>
        .
      </Alert>

      <Card>
        <CardTitle className="mb-4">profile</CardTitle>
        <dl className="space-y-3 text-sm">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <dt className="text-cybermuted">Email</dt>
            <dd className="break-all font-mono text-neon/80">{email}</dd>
          </div>
        </dl>
        <CardDescription className="mt-4 text-xs">
          Signing in uses this address. To change it, contact us — we&apos;ll move your scans and subscription across.
        </CardDescription>
      </Card>

      <Card>
        <CardTitle className="mb-4">plan &amp; billing</CardTitle>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <p className="text-lg font-bold text-neon">{PLAN_LABELS[billingPlan] ?? billingPlan}</p>
            {planStatus === "past_due" && (
              <p className="mt-1 text-xs text-warning">Payment past due — update your card to avoid losing access.</p>
            )}
            {billingPlan === "none" && (
              <p className="mt-1 text-xs text-cybermuted">
                You&apos;re on the free tier.{" "}
                <Link href="/pricing" className="text-neon hover:underline">
                  Compare plans
                </Link>
              </p>
            )}
          </div>
          {billingPlan !== "none" && (
            <Button variant="secondary" onClick={billing.open} disabled={billing.loading}>
              {billing.loading ? "Opening…" : "Manage billing"}
            </Button>
          )}
        </div>
        {billing.error && (
          <Alert variant="danger" className="mt-3">
            {billing.error}
          </Alert>
        )}
      </Card>

      {brandingEnabled && branding && (
        <BrandingSection token={accessToken} initialLogoUrl={branding.logoUrl} initialBrandName={branding.name} />
      )}

      <TeamSection token={accessToken} currentUserId={userId} />

      <TwoFactor />

      <RequestAudit token={accessToken} />

      <AccountDeletion token={accessToken} />
    </div>
  );
}

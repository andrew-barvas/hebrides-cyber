"use client";

import AssetInventory from "@/components/AssetInventory";
import DmarcReports from "@/components/DmarcReports";
import DomainVerification from "@/components/DomainVerification";
import EstateMap from "@/components/EstateMap";
import LockedFeature from "@/components/LockedFeature";
import LookalikeDomains from "@/components/LookalikeDomains";
import MonitoredTargets from "@/components/MonitoredTargets";
import TenantDomainSuggestions from "@/components/TenantDomainSuggestions";
import { useAppSession } from "@/components/app-shell/AppShell";
import { CardDescription, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";
import { planIncludes } from "@/lib/planAccess";

export default function AssetsPage() {
  const { plan, accessToken } = useAppSession();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="$ ./assets"
        title="Assets"
        description="Verify the domains you own, choose which ones we rescan on a schedule, and review everything discovered across your scans."
      />

      {/* Ownership first: it gates every scan, and OnboardingChecklist's
          first step deep-links to this anchor. */}
      <section id="domain-verification" className="scroll-mt-6">
        <DomainVerification />
      </section>

      {/* Basic/Pro/Agency all get scheduled monitoring (E-01) — cadence and
          per-plan target caps are enforced server-side (scanCadence.ts,
          018_monitored_targets_plan_cap.sql); this only mirrors that gate. */}
      {plan !== "none" ? (
        <>
          <MonitoredTargets />
          {planIncludes(plan, "pro") && <TenantDomainSuggestions token={accessToken} />}
        </>
      ) : (
        <LockedFeature
          title="monitored sites"
          description="Rescan your sites automatically — weekly on Basic, daily on Pro and Agency — and get alerted when something new turns up."
          availableOn="Paid plans"
        />
      )}

      <section aria-labelledby="estate-map-heading" className="space-y-3">
        <div>
          <CardTitle id="estate-map-heading">estate map</CardTitle>
          <CardDescription className="mt-1">
            Every host we know about, grouped by domain: whether it answers on the web, when its certificate expires, which services are exposed and what&apos;s open.
          </CardDescription>
        </div>
        <EstateMap token={accessToken} />
      </section>

      <section aria-labelledby="discovered-assets-heading" className="space-y-3">
        <div>
          <CardTitle id="discovered-assets-heading">discovered assets</CardTitle>
          <CardDescription className="mt-1">
            Domains and subdomains found across your scans, with detected CMS and cloud/CDN hints.
          </CardDescription>
        </div>
        <AssetInventory />
      </section>

      {/* Lookalike domains (migration 053) with what to do about each; the
          lookalike alert email links to this anchor. */}
      <section id="lookalikes" aria-labelledby="lookalikes-heading" className="scroll-mt-6 space-y-3">
        <div>
          <CardTitle id="lookalikes-heading">lookalike domains</CardTitle>
          <CardDescription className="mt-1">
            Registered domains one character away from yours, with a certificate already issued: a common setup for phishing your staff or customers. Open one for what to do.
          </CardDescription>
        </div>
        <LookalikeDomains />
      </section>

      {/* DMARC aggregate reports (E-66) — the half of NCSC Mail Check a DNS
          lookup can't show. Panel self-hides before migration 060 or for a
          free account with no ingest URL set. */}
      <section aria-label="DMARC reports">
        <DmarcReports token={accessToken} paidPlan={planIncludes(plan, "basic")} />
      </section>
    </div>
  );
}

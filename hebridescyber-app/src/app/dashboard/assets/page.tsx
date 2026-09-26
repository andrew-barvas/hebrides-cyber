"use client";

import AssetInventory from "@/components/AssetInventory";
import DomainVerification from "@/components/DomainVerification";
import LockedFeature from "@/components/LockedFeature";
import MonitoredTargets from "@/components/MonitoredTargets";
import { useAppSession } from "@/components/app-shell/AppShell";
import { CardDescription, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page-header";

export default function AssetsPage() {
  const { plan } = useAppSession();

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
        <MonitoredTargets />
      ) : (
        <LockedFeature
          title="monitored sites"
          description="Rescan your sites automatically — weekly on Basic, daily on Pro and Agency — and get alerted when something new turns up."
          availableOn="Paid plans"
        />
      )}

      <section aria-labelledby="discovered-assets-heading" className="space-y-3">
        <div>
          <CardTitle id="discovered-assets-heading">discovered assets</CardTitle>
          <CardDescription className="mt-1">
            Domains and subdomains found across your scans, with detected CMS and cloud/CDN hints.
          </CardDescription>
        </div>
        <AssetInventory />
      </section>
    </div>
  );
}

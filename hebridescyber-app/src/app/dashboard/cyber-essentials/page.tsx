"use client";

import CeAssessment from "@/components/CeAssessment";
import EvidencePackButton from "@/components/EvidencePackButton";
import { planIncludes } from "@/lib/planAccess";
import { useAppSession } from "@/components/app-shell/AppShell";
import { PageHeader } from "@/components/ui/page-header";

export default function CyberEssentialsPage() {
  const { accessToken, plan } = useAppSession();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="$ ./cyber-essentials"
        title="Cyber Essentials readiness"
        description="Your latest scan's external evidence combined with the questions only you can answer — host firewalls, device configuration, admin access, endpoint anti-malware and patching — merged into a per-control readiness view. Answers autosave."
      />
      {planIncludes(plan, "pro") && <EvidencePackButton token={accessToken} />}
      <CeAssessment token={accessToken} />
    </div>
  );
}

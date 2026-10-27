"use client";

import SlaDashboard from "@/components/SlaDashboard";
import { useAppSession } from "@/components/app-shell/AppShell";
import { PageHeader } from "@/components/ui/page-header";

export default function SlaPage() {
  const { accessToken, currentClientId } = useAppSession();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="$ ./sla"
        title="Remediation SLAs"
        description="Every open finding across your sites against the fix-by target for its severity, how quickly things actually get fixed, and alerts before a deadline passes."
      />
      <SlaDashboard token={accessToken} client={currentClientId} />
    </div>
  );
}

"use client";

import FindingsExplorer from "@/components/FindingsExplorer";
import { useAppSession } from "@/components/app-shell/AppShell";
import { PageHeader } from "@/components/ui/page-header";

export default function FindingsPage() {
  const { accessToken, currentClientId } = useAppSession();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="$ ./findings"
        title="Findings"
        description="Every open finding across all your sites. Filter, group by check, and accept, mark as false positive or snooze many at once."
      />
      <FindingsExplorer token={accessToken} client={currentClientId} />
    </div>
  );
}

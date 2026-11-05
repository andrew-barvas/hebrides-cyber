"use client";

import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import FindingsExplorer from "@/components/FindingsExplorer";
import { useAppSession } from "@/components/app-shell/AppShell";
import { PageHeader } from "@/components/ui/page-header";

// ?sort=priority (the dashboard's "fix this first" link) opens on the ranked list.
function Explorer({ token }: { token: string | null }) {
  const params = useSearchParams();
  return <FindingsExplorer token={token} initialView={params?.get("sort") === "priority" ? "priority" : "grouped"} />;
}

export default function FindingsPage() {
  const { accessToken } = useAppSession();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="$ ./findings"
        title="Findings"
        description="Every open finding across all your sites. Rank them by what to fix first, filter, group by check, and accept, mark as false positive or snooze many at once."
      />
      <Suspense fallback={null}>
        <Explorer token={accessToken} />
      </Suspense>
    </div>
  );
}

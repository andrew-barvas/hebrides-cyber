"use client";

// /dashboard/engagements — the customer's authorised testing engagements, newest
// first. Each opens its status page, which has the stop button.
import { useEffect, useState } from "react";
import Link from "next/link";
import { useAppSession } from "@/components/app-shell/AppShell";
import { PageHeader } from "@/components/ui/page-header";
import { STATE_LABEL, formatWhen } from "@/lib/engagementStatus";
import type { EngagementSummary } from "@/lib/engagements";

export default function EngagementsPage() {
  const { accessToken } = useAppSession();
  const [rows, setRows] = useState<EngagementSummary[] | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    if (!accessToken) return;
    fetch("/api/engagements", { headers: { Authorization: `Bearer ${accessToken}` } })
      .then(async (r) => (r.ok ? ((await r.json()) as { engagements: EngagementSummary[] }).engagements : Promise.reject()))
      .then(setRows)
      .catch(() => setError(true));
  }, [accessToken]);

  return (
    <>
      <PageHeader title="Testing engagements" description="Authorised tests of the systems you own, with their scope, window and status." />
      {error && (
        <p role="alert" className="text-sm text-danger">
          Couldn&apos;t load your engagements. Refresh to try again.
        </p>
      )}
      {rows && rows.length === 0 && <p className="text-sm text-cybermuted">You have no testing engagements.</p>}
      {rows && rows.length > 0 && (
        <ul className="divide-y divide-cyberborder">
          {rows.map((r) => (
            <li key={r.id} className="flex flex-wrap items-center justify-between gap-2 py-3">
              <Link href={`/dashboard/engagements/${r.id}`} className="font-semibold text-neon hover:underline">
                {r.reference}
                {r.customer_name ? ` (${r.customer_name})` : ""}
              </Link>
              <span className="text-xs text-cybermuted">
                {STATE_LABEL[r.state].title} · {formatWhen(r.window_start)} to {formatWhen(r.window_end)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

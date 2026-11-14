"use client";

// /dashboard/lookout — the customer's Lookout reports (migration 075),
// newest first. Shows an explanation instead of an empty list when there are none.
import { useEffect, useState } from "react";
import Link from "next/link";
import { useAppSession } from "@/components/app-shell/AppShell";
import { PageHeader } from "@/components/ui/page-header";

type Row = { id: string; period_start: string; period_end: string; status: string; published_at: string | null; acknowledged_at: string | null };

export default function LookoutReportsPage() {
  const { accessToken } = useAppSession();
  const [rows, setRows] = useState<Row[] | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    if (!accessToken) return;
    fetch("/api/lookout/reports", { headers: { Authorization: `Bearer ${accessToken}` } })
      .then(async (r) => (r.ok ? ((await r.json()) as { reports: Row[] }).reports : Promise.reject()))
      .then(setRows)
      .catch(() => setError(true));
  }, [accessToken]);

  return (
    <>
      <PageHeader title="Reports" description="Your Lookout exposure review reports, written by our engineers." />
      {error && (
        <p role="alert" className="text-sm text-danger">
          Couldn&apos;t load your reports. Refresh to try again.
        </p>
      )}
      {rows && rows.length === 0 && <p className="text-sm text-cybermuted">No reports yet. With Lookout, your engineer&apos;s report appears here each period.</p>}
      {rows && rows.length > 0 && (
        <ul className="divide-y divide-cyberborder">
          {rows.map((r) => (
            <li key={r.id} className="flex flex-wrap items-center justify-between gap-2 py-3">
              <Link href={`/dashboard/lookout/${r.id}`} className="font-semibold text-neon hover:underline">
                {r.period_start} to {r.period_end}
              </Link>
              <span className="text-xs text-cybermuted">{r.status === "acknowledged" ? "Read" : "New"}</span>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

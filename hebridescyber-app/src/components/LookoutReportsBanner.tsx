"use client";

// Dashboard overview: a short notice when the customer has Lookout reports
// (migration 075), linking to them. Renders nothing for everyone else, so
// scanner-only customers never see an empty "Reports" section.
import { useEffect, useState } from "react";
import Link from "next/link";

export default function LookoutReportsBanner({ token }: { token: string | null }) {
  const [state, setState] = useState<{ total: number; unread: number } | null>(null);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    fetch("/api/lookout/reports", { headers: { Authorization: `Bearer ${token}` } })
      .then(async (r) => (r.ok ? ((await r.json()) as { reports: Array<{ status: string }> }).reports : []))
      .catch(() => [])
      .then((reports) => {
        if (!cancelled) setState({ total: reports.length, unread: reports.filter((r) => r.status === "published").length });
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  if (!state || state.total === 0) return null;
  return (
    <div className="rounded-lg border border-neon/30 bg-neon/10 p-4 text-sm">
      <p className="text-cybertext">
        {state.unread > 0 ? `You have ${state.unread} new Lookout report${state.unread === 1 ? "" : "s"} from your engineer.` : "Your Lookout reports from your engineer."}{" "}
        <Link href="/dashboard/lookout" className="font-semibold text-neon underline-offset-2 hover:underline">
          {state.unread > 0 ? "Read it" : "View reports"}
        </Link>
      </p>
    </div>
  );
}

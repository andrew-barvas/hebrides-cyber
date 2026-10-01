"use client";

// Dashboard overview panel for emerging-threat alerts: CVEs CISA newly added
// to its Known Exploited Vulnerabilities catalog that matched a technology
// and version on one of the account's sites (GET /api/emerging-threats,
// written by the 6-hourly job in src/scripts/check-emerging-threats.ts).
//
// Renders nothing until the data is back, before migration 045, or for an
// account without a paid plan and no alerts — the feature only runs for paid
// plans, so an empty panel there would promise something that never comes.
import { useEffect, useState } from "react";
import Link from "next/link";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export type EmergingThreatAlert = {
  id: string;
  target_host: string;
  cve_id: string;
  confidence: "affected" | "possibly_affected";
  product: string;
  detected_version: string | null;
  kev_date_added: string | null;
  scan_id: string | null;
  matched_at: string;
  notified_at: string | null;
};

const PREVIEW = 5;

const formatDate = (iso: string) =>
  new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });

export default function EmergingThreatsPanel({ token, paidPlan }: { token: string | null; paidPlan: boolean }) {
  const [alerts, setAlerts] = useState<EmergingThreatAlert[] | null>(null);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    fetch("/api/emerging-threats", { headers: { Authorization: `Bearer ${token}` } })
      .then(async (res) => {
        if (!res.ok) return null;
        const body = (await res.json()) as { available?: boolean; alerts?: EmergingThreatAlert[] };
        return body.available ? (body.alerts ?? []) : null;
      })
      .catch(() => null)
      .then((list) => {
        if (!cancelled) setAlerts(list);
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  if (alerts === null) return null;
  if (alerts.length === 0 && !paidPlan) return null;

  return (
    <Card>
      <CardHeader>
        <div className="min-w-0">
          <CardTitle>emerging threats</CardTitle>
          <CardDescription className="mt-1">
            Every 6 hours we check vulnerabilities CISA newly confirms as actively exploited against the software and versions
            your latest scans found.
          </CardDescription>
        </div>
      </CardHeader>

      {alerts.length === 0 ? (
        <p className="text-sm text-cybermuted">No newly exploited vulnerability has matched your sites.</p>
      ) : (
        <ul className="divide-y divide-cyberborder">
          {alerts.slice(0, PREVIEW).map((a) => (
            <li key={a.id} className="flex flex-wrap items-start justify-between gap-2 py-3 first:pt-0 last:pb-0">
              <div className="min-w-0">
                <p className="text-sm font-medium text-cybertext">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(a.cve_id)}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-neon hover:underline"
                  >
                    {a.cve_id}
                  </a>{" "}
                  · {a.product} {a.detected_version ?? <span className="text-cybermuted">(version not visible)</span>}
                </p>
                <p className="truncate text-xs text-cybermuted">
                  {a.target_host}
                  {a.kev_date_added ? ` · exploited-list date ${formatDate(a.kev_date_added)}` : ""}
                  {a.scan_id && (
                    <>
                      {" · "}
                      <Link href={`/dashboard/scans/${a.scan_id}`} className="text-neon hover:underline">
                        latest report
                      </Link>
                    </>
                  )}
                </p>
              </div>
              <span
                className={
                  a.confidence === "affected"
                    ? "shrink-0 rounded border border-danger/30 bg-danger/10 px-2 py-0.5 text-xs font-medium text-danger"
                    : "shrink-0 rounded border border-warning/30 bg-warning/10 px-2 py-0.5 text-xs font-medium text-warning"
                }
              >
                {a.confidence === "affected" ? "Affected" : "Check version"}
              </span>
            </li>
          ))}
        </ul>
      )}
      {alerts.length > PREVIEW && <p className="mt-3 text-xs text-cybermuted">Showing the {PREVIEW} most recent of {alerts.length}.</p>}
    </Card>
  );
}

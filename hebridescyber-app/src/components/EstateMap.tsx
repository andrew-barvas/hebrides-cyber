"use client";

// The estate map (GET /api/estate/map, src/lib/estateMap.ts): every host we
// know about, grouped by domain, with whether it answers on the web, its
// certificate's expiry, exposed services and open issues. Unknown data says
// "not checked", never "fine".

import { useEffect, useState } from "react";
import { Card } from "@/components/ui/card";
import { StatCard } from "@/components/ui/stat-card";
import type { EstateHost, EstateMap as EstateMapData } from "@/lib/estateMap";
import { cn } from "@/lib/utils";

const EXPIRING_DAYS = 30;

function WebCell({ web }: { web: EstateHost["web"] }) {
  if (!web) return <span className="text-cybermuted">not probed</span>;
  const ok = web.statusCode < 400;
  return (
    <span className={cn(ok ? "text-cybertext" : "text-warning")}>
      {web.statusCode}
      {web.title ? <span className="text-cybermuted"> · {web.title.slice(0, 60)}</span> : null}
    </span>
  );
}

function CertCell({ cert }: { cert: EstateHost["certificate"] }) {
  if (!cert) return <span className="text-cybermuted">not checked</span>;
  const days = cert.daysLeft;
  const tone = days === null ? "text-cybertext" : days < 0 ? "text-danger" : days <= EXPIRING_DAYS ? "text-warning" : "text-cybertext";
  return (
    <span className={tone}>
      {days === null ? cert.expiresAt.slice(0, 10) : days < 0 ? `expired ${-days} day${days === -1 ? "" : "s"} ago` : `${days} day${days === 1 ? "" : "s"} left`}
    </span>
  );
}

function IssuesCell({ counts }: { counts: EstateHost["openFindings"] }) {
  const serious = counts.critical + counts.high;
  const other = counts.medium + counts.low;
  if (serious + other === 0) return <span className="text-cybermuted">none open</span>;
  return (
    <span>
      {serious > 0 && <span className="text-danger">{serious} critical/high</span>}
      {serious > 0 && other > 0 && <span className="text-cybermuted"> · </span>}
      {other > 0 && <span className="text-cybertext/80">{other} other</span>}
    </span>
  );
}

export default function EstateMap({ token }: { token: string | null }) {
  const [map, setMap] = useState<EstateMapData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    fetch("/api/estate/map", { headers: { Authorization: `Bearer ${token}` } })
      .then(async (res) => (res.ok ? ((await res.json()) as EstateMapData) : Promise.reject(new Error("Could not load your estate map"))))
      .then(setMap)
      .catch((e: Error) => setError(e.message));
  }, [token]);

  if (error) return <p role="alert" className="text-sm text-danger">{error}</p>;
  if (!map) return <p className="font-mono text-xs text-cybermuted">// loading estate map…</p>;
  if (map.totals.hosts === 0) return <p className="text-sm text-cybermuted">Nothing mapped yet. Your hosts appear here after your first scan.</p>;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Hosts" value={map.totals.hosts} />
        <StatCard label="Answering on the web" value={map.totals.live} />
        <StatCard label={`Certificates expiring in ${EXPIRING_DAYS} days`} value={map.totals.certificatesExpiringSoon} tone={map.totals.certificatesExpiringSoon ? "warning" : "default"} />
        <StatCard label="Hosts with critical/high issues" value={map.totals.withCriticalOrHigh} tone={map.totals.withCriticalOrHigh ? "danger" : "default"} />
      </div>
      {map.domains.map((d) => (
        <Card key={d.domain} className="space-y-2 overflow-x-auto">
          <h3 className="font-mono text-sm font-semibold text-neon">{d.domain}</h3>
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead>
              <tr className="text-xs uppercase text-cybermuted">
                <th className="py-1 pr-3 font-normal">Host</th>
                <th className="py-1 pr-3 font-normal">Web</th>
                <th className="py-1 pr-3 font-normal">Certificate</th>
                <th className="py-1 pr-3 font-normal">Exposed services</th>
                <th className="py-1 font-normal">Open issues</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyberborder">
              {d.hosts.map((h) => (
                <tr key={h.host}>
                  <td className="py-1.5 pr-3 font-mono text-xs break-all">
                    {h.scanId ? (
                      <a href={`/dashboard/scans/${h.scanId}`} className="text-cybertext hover:text-neon hover:underline">
                        {h.host}
                      </a>
                    ) : (
                      h.host
                    )}
                  </td>
                  <td className="py-1.5 pr-3 text-xs"><WebCell web={h.web} /></td>
                  <td className="py-1.5 pr-3 text-xs"><CertCell cert={h.certificate} /></td>
                  <td className="py-1.5 pr-3 text-xs">
                    {h.exposedPorts.length ? <span className="text-warning">{h.exposedPorts.map((p) => `port ${p}`).join(", ")}</span> : <span className="text-cybermuted">none found</span>}
                  </td>
                  <td className="py-1.5 text-xs"><IssuesCell counts={h.openFindings} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      ))}
    </div>
  );
}

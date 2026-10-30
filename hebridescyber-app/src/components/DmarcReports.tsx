"use client";

// Dashboard panel for DMARC aggregate (RUA) reports (E-66). Shows the per-owner
// ingest URL to configure at a mail/forwarding provider's rua= destination, and
// the latest reports once they arrive — who is sending as your domain and how
// much of it aligns (passes SPF/DKIM). Reads GET /api/dmarc/reports and
// GET/POST /api/account/dmarc-ingest-token. Renders nothing until data is back,
// or before migration 060 (available:false), so it stays quiet on servers where
// the feature isn't enabled.
import { useCallback, useEffect, useState } from "react";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

type DmarcRow = { sourceIp: string; count: number; disposition: string; dkim: string; spf: string; headerFrom: string | null };
export type DmarcReport = {
  id: string;
  domain: string;
  org_name: string;
  date_begin: string | null;
  date_end: string | null;
  total_messages: number;
  passing_messages: number;
  failing_messages: number;
  rows: DmarcRow[];
  received_at: string;
};

const PREVIEW = 5;
const formatDate = (iso: string) => new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
const pct = (pass: number, total: number) => (total === 0 ? null : Math.round((pass / total) * 100));

export default function DmarcReports({ token, paidPlan }: { token: string | null; paidPlan: boolean }) {
  const [reports, setReports] = useState<DmarcReport[] | null>(null);
  const [available, setAvailable] = useState(true);
  const [ingestUrl, setIngestUrl] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    fetch("/api/dmarc/reports", { headers: { Authorization: `Bearer ${token}` } })
      .then(async (res) => (res.ok ? ((await res.json()) as { available?: boolean; reports?: DmarcReport[] }) : null))
      .catch(() => null)
      .then((body) => {
        if (cancelled || !body) return;
        setAvailable(body.available !== false);
        setReports(body.available === false ? [] : (body.reports ?? []));
      });
    fetch("/api/account/dmarc-ingest-token", { headers: { Authorization: `Bearer ${token}` } })
      .then(async (res) => (res.ok ? ((await res.json()) as { ingestUrl?: string | null }) : null))
      .catch(() => null)
      .then((body) => {
        if (!cancelled && body) setIngestUrl(body.ingestUrl ?? null);
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  const generate = useCallback(async () => {
    if (!token) return;
    setBusy(true);
    try {
      const res = await fetch("/api/account/dmarc-ingest-token", { method: "POST", headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) {
        const body = (await res.json()) as { ingestUrl?: string };
        setIngestUrl(body.ingestUrl ?? null);
      }
    } finally {
      setBusy(false);
    }
  }, [token]);

  // Quiet unless the feature is on and this is a paid account (or reports exist).
  if (reports === null) return null;
  if (!available) return null;
  if (!paidPlan && reports.length === 0 && !ingestUrl) return null;

  return (
    <Card>
      <CardHeader>
        <div className="min-w-0">
          <CardTitle>DMARC reports</CardTitle>
          <CardDescription className="mt-1">
            The daily aggregate reports mailbox providers send to your domain&apos;s <span className="font-mono">rua=</span> address —
            who is sending mail as you, and how much of it passes SPF/DKIM. This is the half of the retired NCSC Mail Check a
            DNS lookup can&apos;t show.
          </CardDescription>
        </div>
      </CardHeader>

      {/* Ingest URL setup */}
      <div className="rounded-sm border border-cyberborder bg-cyberbg/40 p-3">
        {ingestUrl ? (
          <>
            <p className="text-xs text-cybermuted">Point a mailbox/forwarding provider at this URL to receive your reports:</p>
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <code className="min-w-0 flex-1 truncate rounded-sm bg-cybertext/5 px-2 py-1 font-mono text-xs text-cybertext">{ingestUrl}</code>
              <Button
                variant="secondary"
                onClick={() => {
                  navigator.clipboard?.writeText(ingestUrl).then(() => {
                    setCopied(true);
                    setTimeout(() => setCopied(false), 1500);
                  });
                }}
              >
                {copied ? "Copied" : "Copy"}
              </Button>
              <Button variant="ghost" onClick={generate} disabled={busy}>
                {busy ? "…" : "Rotate"}
              </Button>
            </div>
            <p className="mt-1 text-xs text-cybermuted">Keep this URL private — anyone with it can submit reports to your account.</p>
          </>
        ) : (
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-sm text-cybermuted">Generate an ingest URL to start collecting DMARC reports.</p>
            <Button onClick={generate} disabled={busy}>
              {busy ? "Generating…" : "Generate ingest URL"}
            </Button>
          </div>
        )}
      </div>

      {reports.length === 0 ? (
        <p className="mt-3 text-sm text-cybermuted">No reports received yet. They arrive once a provider forwards them to the URL above.</p>
      ) : (
        <ul className="mt-3 divide-y divide-cyberborder">
          {reports.slice(0, PREVIEW).map((r) => {
            const p = pct(r.passing_messages, r.total_messages);
            return (
              <li key={r.id} className="flex flex-wrap items-start justify-between gap-2 py-3 first:pt-0 last:pb-0">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-cybertext">
                    {r.domain} <span className="text-cybermuted">· via {r.org_name}</span>
                  </p>
                  <p className="truncate text-xs text-cybermuted">
                    {r.total_messages} message{r.total_messages === 1 ? "" : "s"}
                    {r.date_begin ? ` · ${formatDate(r.date_begin)}` : ` · received ${formatDate(r.received_at)}`}
                  </p>
                </div>
                {p !== null && (
                  <span
                    className={
                      p >= 95
                        ? "shrink-0 rounded-sm border border-neon/30 bg-neon/10 px-2 py-0.5 text-xs font-medium text-neon"
                        : p >= 80
                          ? "shrink-0 rounded-sm border border-warning/30 bg-warning/10 px-2 py-0.5 text-xs font-medium text-warning"
                          : "shrink-0 rounded-sm border border-danger/30 bg-danger/10 px-2 py-0.5 text-xs font-medium text-danger"
                    }
                  >
                    {p}% aligned
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {reports.length > PREVIEW && <p className="mt-3 text-xs text-cybermuted">Showing the {PREVIEW} most recent of {reports.length}.</p>}
    </Card>
  );
}

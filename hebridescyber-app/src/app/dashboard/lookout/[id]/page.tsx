"use client";

// /dashboard/lookout/<id> — one Lookout report: the engineer's summary, then
// each finding in priority order with their note, the business impact and who
// should fix it. "I've read this report" records the acknowledgement (it does
// not accept any risk). "Download PDF" gets the dated PDF with the estate
// gallery (/api/lookout/report-pdf); the gallery also shows below.
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { useAppSession } from "@/components/app-shell/AppShell";
import { PageHeader } from "@/components/ui/page-header";
import { Button } from "@/components/ui/button";
import EstateScreenshots from "@/components/EstateScreenshots";

type Report = { id: string; period_start: string; period_end: string; status: string; summary: string; published_at: string | null; acknowledged_at: string | null };
type Item = { id: string; host: string; severity: string; title: string; priority: number; analyst_note: string; business_impact: string; fix_owner: string };

const FIX_OWNER_LABEL: Record<string, string> = { customer: "You", it_supplier: "Your IT supplier", hosting_provider: "Your hosting provider", unknown: "To be agreed" };

export default function LookoutReportPage() {
  const { accessToken } = useAppSession();
  const params = useParams<{ id: string }>();
  const [data, setData] = useState<{ report: Report; items: Item[]; galleryScanId?: string | null } | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!accessToken || !params?.id) return;
    fetch(`/api/lookout/reports/${params.id}`, { headers: { Authorization: `Bearer ${accessToken}` } })
      .then(async (r) => (r.ok ? r.json() : Promise.reject(new Error(r.status === 404 ? "Report not found." : "Couldn't load this report."))))
      .then(setData)
      .catch((e) => setError((e as Error).message));
  }, [accessToken, params]);

  async function acknowledge() {
    if (!accessToken || !data) return;
    setBusy(true);
    const res = await fetch(`/api/lookout/reports/${data.report.id}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ action: "acknowledge" }),
    });
    setBusy(false);
    if (res.ok) {
      const body = (await res.json()) as { acknowledged_at?: string };
      setData({ ...data, report: { ...data.report, status: "acknowledged", acknowledged_at: body.acknowledged_at ?? new Date().toISOString() } });
    } else setError("Couldn't record that. Please try again.");
  }

  async function downloadPdf() {
    if (!accessToken || !data) return;
    setDownloading(true);
    try {
      const res = await fetch(`/api/lookout/report-pdf?id=${encodeURIComponent(data.report.id)}`, { headers: { Authorization: `Bearer ${accessToken}` } });
      if (!res.ok) throw new Error(res.status === 429 ? "You've downloaded a lot of reports. Try again in a little while." : "Couldn't produce the PDF. Please try again.");
      const url = URL.createObjectURL(await res.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = `lookout-report-${data.report.period_end}.pdf`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setDownloading(false);
    }
  }

  if (error) return <p role="alert" className="text-sm text-danger">{error}</p>;
  if (!data) return <p className="text-sm text-cybermuted">Loading…</p>;
  const { report, items } = data;

  return (
    <article className="space-y-6">
      <PageHeader title={`Lookout report: ${report.period_start} to ${report.period_end}`} description={report.published_at ? `Published ${new Date(report.published_at).toLocaleDateString("en-GB")}` : undefined} />
      <div className="print:hidden">
        <Button variant="secondary" size="sm" onClick={downloadPdf} disabled={downloading}>
          {downloading ? "Preparing PDF…" : "Download PDF"}
        </Button>
      </div>
      {report.summary && <p className="whitespace-pre-line text-cybertext">{report.summary}</p>}
      <ol className="space-y-4">
        {items.map((i) => (
          <li key={i.id} className="rounded-lg border border-cyberborder bg-cyberpanel p-4">
            <p className="font-semibold text-cybertext">
              <span className="mr-2 font-mono text-[11px] uppercase text-cybermuted">
                {i.priority}. {i.severity}
              </span>
              {i.title}
            </p>
            <p className="break-all text-xs text-cybermuted">{i.host}</p>
            {i.analyst_note && <p className="mt-2 whitespace-pre-line text-sm text-cybertext/90">{i.analyst_note}</p>}
            {i.business_impact && <p className="mt-2 text-sm text-cybertext/80"><strong>Why it matters:</strong> {i.business_impact}</p>}
            <p className="mt-1 text-xs text-cybermuted">Who fixes it: {FIX_OWNER_LABEL[i.fix_owner] ?? "To be agreed"}</p>
          </li>
        ))}
      </ol>
      {data.galleryScanId && accessToken && <EstateScreenshots scanId={data.galleryScanId} token={accessToken} />}
      <div className="print:hidden">
        {report.status === "acknowledged" ? (
          <p className="text-sm text-cybermuted">You marked this report as read on {new Date(report.acknowledged_at!).toLocaleDateString("en-GB")}.</p>
        ) : (
          <Button onClick={acknowledge} disabled={busy}>
            {busy ? "Saving…" : "I've read this report"}
          </Button>
        )}
        <p className="mt-2 text-xs text-cybermuted">Marking it as read tells your engineer you&apos;ve seen it. It doesn&apos;t mean you accept any of the risks it describes.</p>
      </div>
    </article>
  );
}

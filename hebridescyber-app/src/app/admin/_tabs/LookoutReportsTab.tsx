"use client";

// Admin: write Lookout reports (migration 075, src/lib/lookoutReports.ts).
// Pick a customer, create a draft (pre-filled from their ranking and the
// period's changes), edit the summary and each item's note, impact and
// order, then publish. The customer reads it at /dashboard/lookout/<id>.
import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../_shared";

type ReportRow = { id: string; customer: string; period_start: string; period_end: string; status: string; published_at: string | null; acknowledged_at: string | null };
type Item = { id: string; host: string; check_id: string; severity: string; title: string; included: boolean; priority: number; analyst_note: string; business_impact: string; fix_owner: string };
type Detail = { report: ReportRow & { summary: string }; items: Item[] };

const FIX_OWNERS: Array<[string, string]> = [
  ["customer", "Customer"],
  ["it_supplier", "IT supplier"],
  ["hosting_provider", "Hosting provider"],
  ["unknown", "Unknown"],
];

export default function LookoutReportsTab({ token }: { token: string }) {
  const [customer, setCustomer] = useState("");
  const [periodDays, setPeriodDays] = useState<7 | 30 | 90>(30);
  const [reports, setReports] = useState<ReportRow[]>([]);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loadList = useCallback(() => {
    const q = customer.trim() ? `?customer=${encodeURIComponent(customer.trim())}` : "";
    apiFetch<{ reports: ReportRow[] }>(`/api/admin/lookout/reports${q}`, token)
      .then((r) => setReports(r.reports))
      .catch((e) => setMessage((e as Error).message));
  }, [customer, token]);

  useEffect(() => {
    loadList();
  }, [loadList]);

  async function open(id: string) {
    setMessage(null);
    setDetail(await apiFetch<Detail>(`/api/admin/lookout/reports/${id}`, token));
  }

  async function create() {
    setBusy(true);
    setMessage(null);
    try {
      const r = await apiFetch<{ report: ReportRow }>("/api/admin/lookout/reports", token, { method: "POST", body: JSON.stringify({ customer: customer.trim(), period_days: periodDays }) });
      loadList();
      await open(r.report.id);
    } catch (e) {
      setMessage((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function save(status?: "published" | "draft") {
    if (!detail) return;
    setBusy(true);
    setMessage(null);
    try {
      await apiFetch(`/api/admin/lookout/reports/${detail.report.id}`, token, {
        method: "PATCH",
        body: JSON.stringify({
          summary: detail.report.summary,
          items: detail.items.map(({ id, included, priority, analyst_note, business_impact, fix_owner }) => ({ id, included, priority, analyst_note, business_impact, fix_owner })),
          ...(status ? { status } : {}),
        }),
      });
      setMessage(status === "published" ? "Published. The customer can now read it." : status === "draft" ? "Moved back to draft." : "Saved.");
      await open(detail.report.id);
      loadList();
    } catch (e) {
      setMessage((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const setItem = (id: string, patch: Partial<Item>) => setDetail((d) => (d ? { ...d, items: d.items.map((i) => (i.id === id ? { ...i, ...patch } : i)) } : d));
  const frozen = detail?.report.status === "acknowledged";

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end gap-3">
        <label className="text-sm">
          <span className="block text-cybermuted">Customer user id</span>
          <input value={customer} onChange={(e) => setCustomer(e.target.value)} className="mt-1 w-80 rounded-md border border-cyberborder bg-cyberbg px-2 py-1 font-mono text-xs text-cybertext" placeholder="uuid (blank lists every report)" />
        </label>
        <label className="text-sm">
          <span className="block text-cybermuted">Period</span>
          <select value={periodDays} onChange={(e) => setPeriodDays(Number(e.target.value) as 7 | 30 | 90)} className="mt-1 rounded-md border border-cyberborder bg-cyberbg px-2 py-1 text-cybertext">
            <option value={7}>7 days</option>
            <option value={30}>30 days</option>
            <option value={90}>90 days</option>
          </select>
        </label>
        <button type="button" onClick={create} disabled={busy || !/^[0-9a-f-]{36}$/i.test(customer.trim())} className="rounded-md bg-neon px-3 py-1.5 text-sm font-semibold text-cyberbg disabled:opacity-50">
          New draft report
        </button>
      </div>
      {message && (
        <p role="status" className="text-sm text-cybertext">
          {message}
        </p>
      )}

      <table className="w-full text-left text-sm">
        <thead className="text-cybermuted">
          <tr>
            <th className="py-1">Period</th>
            <th>Customer</th>
            <th>Status</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {reports.map((r) => (
            <tr key={r.id} className="border-t border-cyberborder">
              <td className="py-1">
                {r.period_start} to {r.period_end}
              </td>
              <td className="font-mono text-xs">{r.customer}</td>
              <td>{r.status}</td>
              <td>
                <button type="button" onClick={() => open(r.id)} className="text-neon hover:underline">
                  Open
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {detail && (
        <section className="space-y-4 rounded-lg border border-cyberborder p-4">
          <h3 className="font-semibold">
            Report {detail.report.period_start} to {detail.report.period_end} · {detail.report.status}
          </h3>
          {frozen && <p className="text-sm text-warning">The customer has acknowledged this report, so it can no longer be changed.</p>}
          <label className="block text-sm">
            <span className="text-cybermuted">Summary for the customer</span>
            <textarea value={detail.report.summary} disabled={frozen} onChange={(e) => setDetail({ ...detail, report: { ...detail.report, summary: e.target.value } })} rows={5} className="mt-1 w-full rounded-md border border-cyberborder bg-cyberbg p-2 text-cybertext" />
          </label>
          <ol className="space-y-3">
            {detail.items.map((i) => (
              <li key={i.id} className="rounded-md border border-cyberborder p-3 text-sm">
                <div className="flex flex-wrap items-center gap-3">
                  <input type="number" min={1} value={i.priority} disabled={frozen} onChange={(e) => setItem(i.id, { priority: Number(e.target.value) || 1 })} className="w-16 rounded-md border border-cyberborder bg-cyberbg px-1 text-cybertext" aria-label={`Priority for ${i.title}`} />
                  <label className="flex items-center gap-1">
                    <input type="checkbox" checked={i.included} disabled={frozen} onChange={(e) => setItem(i.id, { included: e.target.checked })} /> include
                  </label>
                  <span className="font-mono text-[11px] uppercase">{i.severity}</span>
                  <span className="font-semibold">{i.title}</span>
                  <span className="break-all text-xs text-cybermuted">{i.host}</span>
                </div>
                <textarea value={i.analyst_note} disabled={frozen} onChange={(e) => setItem(i.id, { analyst_note: e.target.value })} rows={2} placeholder="What this means for them and what to do" className="mt-2 w-full rounded-md border border-cyberborder bg-cyberbg p-2 text-cybertext" />
                <div className="mt-2 flex flex-wrap gap-3">
                  <input value={i.business_impact} disabled={frozen} onChange={(e) => setItem(i.id, { business_impact: e.target.value })} placeholder="Business impact, in one line" className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-2 py-1 text-cybertext" />
                  <select value={i.fix_owner} disabled={frozen} onChange={(e) => setItem(i.id, { fix_owner: e.target.value })} className="rounded-md border border-cyberborder bg-cyberbg px-2 text-cybertext" aria-label={`Who fixes ${i.title}`}>
                    {FIX_OWNERS.map(([v, l]) => (
                      <option key={v} value={v}>
                        {l}
                      </option>
                    ))}
                  </select>
                </div>
              </li>
            ))}
          </ol>
          {!frozen && (
            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={() => save()} disabled={busy} className="rounded-md border border-cyberborder px-3 py-1.5 text-sm">
                Save
              </button>
              {detail.report.status === "draft" ? (
                <button type="button" onClick={() => save("published")} disabled={busy} className="rounded-md bg-neon px-3 py-1.5 text-sm font-semibold text-cyberbg">
                  Save and publish
                </button>
              ) : (
                <button type="button" onClick={() => save("draft")} disabled={busy} className="rounded-md border border-warning px-3 py-1.5 text-sm text-warning">
                  Unpublish to correct
                </button>
              )}
            </div>
          )}
        </section>
      )}
    </div>
  );
}

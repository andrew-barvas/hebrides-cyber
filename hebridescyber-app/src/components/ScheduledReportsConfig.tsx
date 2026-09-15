"use client";

import { useEffect, useState, useCallback } from "react";
import { supabase } from "@/lib/supabaseClient";

type ScheduledReport = {
  id: string;
  target_url: string | null;
  frequency: "daily" | "weekly" | "monthly";
  format: "pdf" | "csv" | "json";
  recipients: string[];
  enabled: boolean;
  last_sent: string | null;
  next_due: string | null;
};

export default function ScheduledReportsConfig() {
  const [reports, setReports] = useState<ScheduledReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const [frequency, setFrequency] = useState<"daily" | "weekly" | "monthly">("weekly");
  const [format, setFormat] = useState<"csv" | "json">("csv");
  const [recipients, setRecipients] = useState("");

  const loadReports = useCallback(async () => {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return;

    const res = await fetch("/api/account/scheduled-reports", {
      headers: { Authorization: `Bearer ${session.access_token}` },
    });
    if (res.ok) {
      const json = await res.json();
      setReports(json.reports ?? []);
    }
    setLoading(false);
  }, []);

  useEffect(() => { loadReports(); }, [loadReports]);

  async function createReport(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setMessage(null);

    const { data: { session } } = await supabase.auth.getSession();
    if (!session) { setSaving(false); return; }

    const recipientList = recipients.split(",").map((r) => r.trim()).filter(Boolean);
    if (recipientList.length === 0) {
      setMessage("Enter at least one recipient email.");
      setSaving(false);
      return;
    }

    const res = await fetch("/api/account/scheduled-reports", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        targetUrl: null,
        frequency,
        format,
        recipients: recipientList,
      }),
    });

    if (res.ok) {
      setMessage("Report schedule created.");
      setShowForm(false);
      setRecipients("");
      await loadReports();
    } else {
      const err = await res.json().catch(() => ({ error: "Failed" }));
      setMessage(err.error ?? "Failed to create schedule.");
    }
    setSaving(false);
  }

  async function toggleReport(id: string, enabled: boolean) {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return;

    await fetch("/api/account/scheduled-reports", {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ id, enabled }),
    });
    await loadReports();
  }

  async function deleteReport(id: string) {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return;

    await fetch("/api/account/scheduled-reports", {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ id }),
    });
    await loadReports();
  }

  if (loading) return null;

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <div className="flex items-center justify-between mb-3">
        <h2 className="font-mono text-xs text-cybertext/40 uppercase tracking-wide">// scheduled reports</h2>
        <button
          onClick={() => setShowForm(!showForm)}
          className="rounded-md border border-cyberborder px-3 py-1.5 text-xs text-cybertext/70 hover:border-neon hover:text-neon transition-colors"
        >
          {showForm ? "Cancel" : "+ New schedule"}
        </button>
      </div>

      {showForm && (
        <form onSubmit={createReport} className="mb-4 space-y-3 rounded-lg border border-cyberborder bg-cyberbg/40 p-4">
          <div className="flex flex-wrap gap-3">
            <label className="flex flex-col gap-1 text-xs text-cybertext/60">
              Frequency
              <select
                value={frequency}
                onChange={(e) => setFrequency(e.target.value as typeof frequency)}
                className="rounded-md border border-cyberborder bg-cyberbg px-2 py-1.5 text-xs text-cybertext"
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </label>
            <label className="flex flex-col gap-1 text-xs text-cybertext/60">
              Format
              <select
                value={format}
                onChange={(e) => setFormat(e.target.value as typeof format)}
                className="rounded-md border border-cyberborder bg-cyberbg px-2 py-1.5 text-xs text-cybertext"
              >
                <option value="csv">CSV</option>
                <option value="json">JSON</option>
              </select>
            </label>
          </div>
          <label className="flex flex-col gap-1 text-xs text-cybertext/60">
            Recipients (comma-separated emails)
            <input
              type="text"
              value={recipients}
              onChange={(e) => setRecipients(e.target.value)}
              placeholder="security@example.com, cto@example.com"
              className="rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-xs text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none"
            />
          </label>
          <button
            type="submit"
            disabled={saving}
            className="rounded-md bg-neon/20 border border-neon/30 px-4 py-2 text-xs font-semibold text-neon hover:bg-neon/30 disabled:opacity-50 transition-colors"
          >
            {saving ? "Creating…" : "Create schedule"}
          </button>
        </form>
      )}

      {message && <p className="mb-3 text-xs text-neon">{message}</p>}

      {reports.length === 0 ? (
        <p className="text-xs text-cybertext/40">No scheduled reports yet. Create one to receive periodic security summaries by email.</p>
      ) : (
        <div className="space-y-2">
          {reports.map((r) => (
            <div key={r.id} className="flex items-center gap-3 rounded-lg border border-cyberborder bg-cyberbg/40 px-4 py-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className={`inline-block h-2 w-2 rounded-full flex-shrink-0 ${r.enabled ? "bg-neon" : "bg-cybertext/20"}`} />
                  <span className="text-sm text-cybertext font-medium capitalize">{r.frequency}</span>
                  <span className="text-xs text-cybertext/40 uppercase">{r.format}</span>
                </div>
                <p className="text-xs text-cybertext/50 mt-0.5 truncate">
                  {r.recipients.join(", ")}
                  {r.last_sent && <span className="ml-2">· Last sent {new Date(r.last_sent).toLocaleDateString()}</span>}
                </p>
              </div>
              <button
                onClick={() => toggleReport(r.id, !r.enabled)}
                className={`rounded-md border px-3 py-1 text-xs transition-colors ${
                  r.enabled
                    ? "border-neon/30 text-neon hover:bg-neon/10"
                    : "border-cyberborder text-cybertext/40 hover:border-neon hover:text-neon"
                }`}
              >
                {r.enabled ? "Pause" : "Resume"}
              </button>
              <button
                onClick={() => deleteReport(r.id)}
                className="rounded-md border border-cyberborder px-3 py-1 text-xs text-red-400/70 hover:border-red-400/30 hover:text-red-400 transition-colors"
              >
                Delete
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

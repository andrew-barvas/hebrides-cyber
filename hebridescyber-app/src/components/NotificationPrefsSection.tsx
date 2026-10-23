"use client";

import { useCallback, useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";

type Severity = "info" | "low" | "medium" | "high" | "critical";

export default function NotificationPrefsSection() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const [emailEnabled, setEmailEnabled] = useState(true);
  const [scoreThreshold, setScoreThreshold] = useState<number | null>(null);
  const [severityMin, setSeverityMin] = useState<Severity | null>(null);

  const load = useCallback(async () => {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return;
    try {
      const res = await fetch("/api/account/notification-prefs", {
        headers: { Authorization: `Bearer ${session.access_token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setEmailEnabled(data.notify_email ?? true);
        setScoreThreshold(data.notify_score_threshold ?? null);
        setSeverityMin(data.notify_severity_min ?? null);
      }
    } catch { /* best effort */ }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  async function save() {
    setSaving(true);
    setMessage(null);
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) { setSaving(false); return; }
    try {
      const res = await fetch("/api/account/notification-prefs", {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${session.access_token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          notify_email: emailEnabled,
          notify_score_threshold: scoreThreshold,
          notify_severity_min: severityMin,
        }),
      });
      if (res.ok) {
        setMessage("Saved.");
      } else {
        const body = await res.json().catch(() => ({ error: "Failed to save" }));
        setMessage(body.error ?? "Failed to save");
      }
    } catch {
      setMessage("Failed to save");
    }
    setSaving(false);
  }

  if (loading) return null;

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <h2 className="mb-1 font-mono text-xs text-cybermuted uppercase tracking-wide">
        // email notifications
      </h2>
      <p className="mb-4 text-xs text-cybertext/60">
        Get an email when a scan completes. Set thresholds to avoid alert fatigue
        — only hear about scans that need attention.
      </p>

      <div className="space-y-4">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={emailEnabled}
            onChange={(e) => setEmailEnabled(e.target.checked)}
            className="h-4 w-4 rounded border-cyberborder bg-cyberbg text-neon focus:ring-neon"
          />
          <span className="text-sm text-cybertext/80">
            Send email on scan completion
          </span>
        </label>

        {emailEnabled && (
          <div className="space-y-3 pl-7">
            <div>
              <label className="block text-xs text-cybertext/60 mb-1">
                Score threshold (only alert when score drops below)
              </label>
              <div className="flex flex-wrap items-center gap-2">
                <input
                  type="number"
                  min={0}
                  max={100}
                  value={scoreThreshold ?? ""}
                  onChange={(e) =>
                    setScoreThreshold(e.target.value ? parseInt(e.target.value, 10) : null)
                  }
                  placeholder="Any score"
                  className="w-28 rounded-md border border-cyberborder bg-cyberbg px-3 py-1.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
                />
                <span className="text-xs text-cybermuted">
                  {scoreThreshold != null
                    ? `Alert when score < ${scoreThreshold}`
                    : "Alert on every scan"}
                </span>
              </div>
            </div>

            <div>
              <label className="block text-xs text-cybertext/60 mb-1">
                Minimum new-finding severity
              </label>
              <select
                value={severityMin ?? ""}
                onChange={(e) =>
                  setSeverityMin((e.target.value || null) as Severity | null)
                }
                className="w-full sm:w-auto rounded-md border border-cyberborder bg-cyberbg px-3 py-1.5 text-sm text-cybertext focus:border-neon focus:outline-none transition-colors"
              >
                <option value="">Any new finding</option>
                <option value="low">Low or higher</option>
                <option value="medium">Medium or higher</option>
                <option value="high">High or higher</option>
                <option value="critical">Critical only</option>
              </select>
            </div>
          </div>
        )}

        <button
          onClick={save}
          disabled={saving}
          className="rounded-md border border-cyberborder px-4 py-2 text-sm text-cybertext/70 hover:border-neon hover:text-neon disabled:opacity-50 transition-colors"
        >
          {saving ? "Saving…" : "Save preferences"}
        </button>
        {message && (
          <p className={`text-xs ${message === "Saved." ? "text-neon" : "text-red-400"}`}>
            {message}
          </p>
        )}
      </div>
    </div>
  );
}

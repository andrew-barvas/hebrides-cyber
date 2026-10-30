"use client";

// Uptime monitoring via the customer's OWN UptimeRobot account (Pro and above;
// the integrations page renders a LockedFeature below that). Hebrides never
// resells UptimeRobot: UptimeRobot's terms bar that, so the customer pastes
// their own API key, we create monitors for their verified sites in their
// account, and this card shows what UptimeRobot reports. See
// docs/ARCHITECTURE-NOTES.md, "Uptime monitoring".
//
// The saved key is never sent back to the browser: status comes from
// GET /api/uptime/status, which returns monitor rows and sync times only.
import { useCallback, useEffect, useState } from "react";
import { getSession } from "@/lib/auth";
import { uptimeStatusLabel } from "@/lib/uptimeLabels";
import type { UptimeStatus } from "@/lib/uptimeProvider";

type Monitor = {
  target_url: string;
  last_status: UptimeStatus | null;
  last_status_at: string | null;
  state_duration_seconds: number | null;
  last_checked_at: string | null;
  /** The last sync did not find this monitor in UptimeRobot, so last_status is stale. */
  missing?: boolean;
};

type Status = {
  allowed: boolean;
  connected: boolean;
  lastSyncAt?: string | null;
  lastError?: string | null;
  refreshError?: string;
  monitors: Monitor[];
  unmonitored: string[];
};

type CreateResult = { targetUrl: string; result: string; error?: string };

const RESULT_TEXT: Record<string, string> = {
  created: "monitor created",
  adopted: "existing monitor linked",
  exists: "already monitored",
  not_monitored: "not one of your monitored sites",
  not_verified: "verify this domain first (Assets)",
  invalid_url: "not a valid URL",
  skipped: "skipped, try again in a minute",
};

function formatDuration(seconds: number | null): string | null {
  if (seconds === null) return null;
  if (seconds < 90) return "under a minute";
  const minutes = Math.round(seconds / 60);
  if (minutes < 90) return `${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} h`;
  return `${Math.round(hours / 24)} days`;
}

export default function UptimeMonitoringConfig() {
  const [status, setStatus] = useState<Status | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const token = useCallback(async (): Promise<string | null> => {
    const session = await getSession();
    return session ? session.access_token : null;
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const t = await token();
      if (!t) {
        setError("Not signed in.");
        return;
      }
      const res = await fetch("/api/uptime/status", { headers: { Authorization: `Bearer ${t}` } });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not load uptime status");
      setStatus(body as Status);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    load();
  }, [load]);

  async function call(url: string, method: "POST" | "DELETE", body?: unknown) {
    const t = await token();
    if (!t) throw new Error("Not signed in.");
    const res = await fetch(url, {
      method,
      headers: { Authorization: `Bearer ${t}`, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error ?? "Request failed");
    return json;
  }

  async function connect(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setMessage(null);
    setBusy(true);
    try {
      await call("/api/account/uptime-integration", "POST", { apiKey: apiKey.trim() });
      setApiKey("");
      setMessage("Connected. Now create monitors for your verified sites.");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    setError(null);
    setMessage(null);
    setBusy(true);
    try {
      await call("/api/account/uptime-integration", "DELETE");
      setMessage("Disconnected. Your monitors in UptimeRobot are untouched.");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function createMonitors() {
    if (!status || status.unmonitored.length === 0) return;
    setError(null);
    setMessage(null);
    setBusy(true);
    try {
      const { results } = (await call("/api/uptime/monitors", "POST", { targetUrls: status.unmonitored })) as { results: CreateResult[] };
      setMessage(results.map((r) => `${r.targetUrl}: ${r.result === "error" ? (r.error ?? "failed") : (RESULT_TEXT[r.result] ?? r.result)}`).join(" · "));
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <details className="rounded-lg border border-cyberborder bg-cyberpanel">
      <summary className="cursor-pointer px-5 py-4 text-sm font-semibold text-cybertext/80 hover:text-cybertext transition-colors">
        Uptime monitoring <span className="font-normal text-cybermuted">(your UptimeRobot account, alerts here and by email)</span>
      </summary>
      <div className="space-y-4 px-5 pb-5 pt-1">
        <p className="text-sm text-cybertext/60">
          Connect your own UptimeRobot account (the free plan checks every 5 minutes). We create monitors for your verified sites in your account, show their status here, and send one message when
          a site goes down and one when it recovers. Your monitors stay in your account, and UptimeRobot&rsquo;s terms apply to it.
        </p>

        {loading ? (
          <p className="font-mono text-xs text-cybermuted">{"// loading…"}</p>
        ) : status?.connected ? (
          <>
            {status.monitors.length > 0 ? (
              <ul className="space-y-2">
                {status.monitors.map((m) => {
                  const label = uptimeStatusLabel(m.last_status, m.missing);
                  const since = m.missing ? null : formatDuration(m.state_duration_seconds);
                  return (
                    <li key={m.target_url} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-cyberborder p-3 text-sm">
                      <span className="break-all text-cybertext/80">{m.target_url}</span>
                      <span className={`font-semibold ${label.className}`}>
                        {label.text}
                        {since && m.last_status && m.last_status !== "unknown" ? <span className="font-normal text-cybermuted"> for {since}</span> : null}
                      </span>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="text-sm text-cybermuted">No monitors yet.</p>
            )}

            {status.monitors.some((m) => m.missing) && (
              <p className="text-xs text-cybermuted">
                A monitor marked &ldquo;not found&rdquo; was deleted or moved in UptimeRobot. To recreate it, disconnect and connect again, then create monitors.
              </p>
            )}

            {status.unmonitored.length > 0 && (
              <button
                type="button"
                onClick={createMonitors}
                disabled={busy}
                className="rounded-md bg-neon px-4 py-2.5 text-sm font-semibold text-cyberbg hover:opacity-90 disabled:opacity-50 shadow-glowsm transition-opacity"
              >
                {busy ? "Working…" : `Create monitors for ${status.unmonitored.length} site${status.unmonitored.length === 1 ? "" : "s"}`}
              </button>
            )}

            {status.refreshError && (
              <p className="text-sm text-warning" role="status">
                Showing the last known status. {status.refreshError}
              </p>
            )}
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-cybermuted">
              <span>{status.lastSyncAt ? `Last checked with UptimeRobot ${new Date(status.lastSyncAt).toLocaleString()}` : "Not checked yet"}</span>
              <button type="button" onClick={disconnect} disabled={busy} className="hover:text-danger disabled:opacity-40 transition-colors">
                Disconnect
              </button>
            </div>
          </>
        ) : (
          <form onSubmit={connect} className="space-y-2">
            <label htmlFor="uptimerobot-key" className="block text-xs text-cybertext/60">
              UptimeRobot API key
            </label>
            <input
              id="uptimerobot-key"
              type="password"
              required
              autoComplete="off"
              placeholder="From UptimeRobot → Integrations → API"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-hidden transition-colors"
            />
            <p className="text-xs text-cybermuted">
              Create a free account at{" "}
              <a href="https://uptimerobot.com" target="_blank" rel="noopener noreferrer" className="underline hover:text-neon">
                uptimerobot.com
              </a>
              . The key is stored encrypted and never shown again.
            </p>
            <button disabled={busy} className="rounded-md bg-neon px-4 py-2.5 text-sm font-semibold text-cyberbg hover:opacity-90 disabled:opacity-50 shadow-glowsm transition-opacity">
              {busy ? "Connecting…" : "Connect"}
            </button>
          </form>
        )}

        {error && (
          <p className="text-sm text-danger" role="alert">
            {error}
          </p>
        )}
        {message && <p className="text-sm text-neon">{message}</p>}
      </div>
    </details>
  );
}

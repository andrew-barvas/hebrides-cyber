"use client";

// E-54: PagerDuty / Opsgenie on-call alert integration — account-settings
// panel mirroring TicketIntegration.tsx's structure. Unlike Jira/Linear
// (where the UI treats "connected" as a single latest row), an owner can
// have BOTH a pagerduty and an opsgenie row at once — src/lib/oncallAlerts.ts
// fires to every configured provider — so this renders a list rather than a
// single status card.
import { useCallback, useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";
import { getSession } from "@/lib/auth";

type Provider = "pagerduty" | "opsgenie";

// Only non-secret columns — pagerduty_routing_key/opsgenie_api_key are never
// requested back from the browser once saved, same application-layer rule as
// TicketIntegration.tsx (Postgres RLS is row-level, not column-level).
type Connection = {
  provider: Provider;
  region: "us" | "eu" | null;
  created_at: string;
};

const PROVIDER_LABELS: Record<Provider, string> = {
  pagerduty: "PagerDuty",
  opsgenie: "Opsgenie",
};

export default function OncallIntegrationConfig() {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(true);
  const [provider, setProvider] = useState<Provider>("pagerduty");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const [routingKey, setRoutingKey] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [region, setRegion] = useState<"us" | "eu">("us");

  const load = useCallback(async () => {
    setLoading(true);
    const { data } = await supabase
      .from("ticket_integrations")
      .select("provider, region, created_at")
      .in("provider", ["pagerduty", "opsgenie"]);
    setConnections((data as Connection[] | null) ?? []);
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function withToken(): Promise<string | null> {
    const session = await getSession();
    if (!session) {
      setError("Not signed in.");
      return null;
    }
    return session.access_token;
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setMessage(null);
    const token = await withToken();
    if (!token) return;
    setBusy(true);
    try {
      const body =
        provider === "pagerduty"
          ? { provider, routingKey: routingKey.trim() }
          : { provider, apiKey: apiKey.trim(), region };

      const res = await fetch("/api/account/oncall-integration", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const responseBody = await res.json();
      if (!res.ok) throw new Error(responseBody.error ?? "Could not save on-call integration");
      setMessage(`Connected to ${PROVIDER_LABELS[provider]} — new Critical findings will page this on-call channel.`);
      setRoutingKey("");
      setApiKey("");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function disconnect(p: Provider) {
    setError(null);
    setMessage(null);
    const token = await withToken();
    if (!token) return;
    setBusy(true);
    try {
      const res = await fetch("/api/account/oncall-integration", {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ provider: p }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not disconnect");
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
        On-call alerting <span className="font-normal text-cybermuted">(page PagerDuty/Opsgenie on new critical findings)</span>
      </summary>
      <div className="px-5 pb-5 pt-1 space-y-4">
        <p className="text-sm text-cybertext/60">
          Connect PagerDuty and/or Opsgenie so a new Critical severity finding pages your on-call
          rotation directly, instead of waiting for the next scheduled review. The incident/alert
          resolves automatically once a later scan confirms the finding is fixed.
        </p>

        {loading ? (
          <p className="font-mono text-xs text-cybermuted">// loading…</p>
        ) : connections.length > 0 ? (
          <ul className="space-y-2">
            {connections.map((c) => (
              <li
                key={c.provider}
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-cyberborder p-3"
              >
                <div className="text-sm text-cybertext/70">
                  Connected to <span className="font-semibold text-neon">{PROVIDER_LABELS[c.provider]}</span>
                  {c.provider === "opsgenie" && c.region && (
                    <span className="text-cybermuted"> — {c.region.toUpperCase()} region</span>
                  )}
                </div>
                <button
                  onClick={() => disconnect(c.provider)}
                  disabled={busy}
                  className="text-xs text-cybermuted hover:text-red-400 disabled:opacity-40 transition-colors"
                >
                  Disconnect
                </button>
              </li>
            ))}
          </ul>
        ) : null}

        {connections.length < 2 && (
          <>
            <div className="flex gap-2">
              {(["pagerduty", "opsgenie"] as const)
                .filter((p) => !connections.some((c) => c.provider === p))
                .map((p) => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setProvider(p)}
                    className={`rounded-full px-3 py-1 text-xs font-mono border transition-colors ${
                      provider === p
                        ? "bg-neon text-cyberbg border-neon"
                        : "border-cyberborder text-cybertext/60 hover:border-neon hover:text-neon"
                    }`}
                  >
                    {PROVIDER_LABELS[p]}
                  </button>
                ))}
            </div>

            {!connections.some((c) => c.provider === provider) && (
              <form onSubmit={save} className="space-y-2">
                {provider === "pagerduty" ? (
                  <input
                    type="password"
                    required
                    placeholder="PagerDuty Events API v2 integration routing key"
                    value={routingKey}
                    onChange={(e) => setRoutingKey(e.target.value)}
                    className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
                  />
                ) : (
                  <>
                    <input
                      type="password"
                      required
                      placeholder="Opsgenie API key"
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
                    />
                    <div>
                      <label className="block text-xs text-cybertext/60 mb-1">Region</label>
                      <select
                        value={region}
                        onChange={(e) => setRegion(e.target.value as "us" | "eu")}
                        className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext focus:border-neon focus:outline-none transition-colors"
                      >
                        <option value="us">US</option>
                        <option value="eu">EU</option>
                      </select>
                    </div>
                  </>
                )}
                <button
                  disabled={busy}
                  className="rounded-md bg-neon px-4 py-2.5 text-sm font-semibold text-cyberbg hover:opacity-90 disabled:opacity-50 shadow-glowsm transition-opacity"
                >
                  {busy ? "Connecting…" : "Connect"}
                </button>
              </form>
            )}
          </>
        )}

        {error && (
          <p className="text-sm text-red-400" role="alert">
            {error}
          </p>
        )}
        {message && <p className="text-sm text-neon">{message}</p>}
      </div>
    </details>
  );
}

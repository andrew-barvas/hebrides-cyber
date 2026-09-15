"use client";

import { useCallback, useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";
import { getSession } from "@/lib/auth";

type Provider = "jira" | "linear";

// Only non-secret columns — jira_api_token/linear_api_key are never
// requested back from the browser once saved, an application-layer rule
// (Postgres RLS is row-level, not column-level) — see
// sql/migrations/013_ticket_integrations.sql's header.
type IntegrationStatus = {
  provider: Provider;
  jira_base_url: string | null;
  jira_project_key: string | null;
  linear_team_id: string | null;
  auto_close_enabled: boolean | null;
};

export default function TicketIntegration() {
  const [status, setStatus] = useState<IntegrationStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [provider, setProvider] = useState<Provider>("jira");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  // Jira fields
  const [jiraBaseUrl, setJiraBaseUrl] = useState("");
  const [jiraEmail, setJiraEmail] = useState("");
  const [jiraApiToken, setJiraApiToken] = useState("");
  const [jiraProjectKey, setJiraProjectKey] = useState("");

  // Linear fields
  const [linearApiKey, setLinearApiKey] = useState("");
  const [linearTeamId, setLinearTeamId] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    // Ordered + limited rather than a bare .maybeSingle(): the table is
    // unique on (owner, provider), so an owner who connected both Jira and
    // Linear has two rows and maybeSingle() would error on exactly that
    // account. Newest connection wins, matching create-ticket.ts.
    const { data } = await supabase
      .from("ticket_integrations")
      .select("provider, jira_base_url, jira_project_key, linear_team_id, auto_close_enabled")
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    setStatus((data as IntegrationStatus | null) ?? null);
    setLoading(false);
  }, []);

  async function setAutoClose(enabled: boolean) {
    setError(null);
    setMessage(null);
    const token = await withToken();
    if (!token || !status) return;
    setBusy(true);
    try {
      const res = await fetch("/api/account/ticket-integration", {
        method: "PATCH",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ provider: status.provider, autoCloseEnabled: enabled }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not update auto-close");
      setMessage(
        enabled
          ? "Auto-close on. Tickets will be closed automatically once a later scan confirms the finding is gone."
          : "Auto-close off. Tickets stay open until you close them yourself."
      );
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

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
        provider === "jira"
          ? { provider, baseUrl: jiraBaseUrl.trim(), email: jiraEmail.trim(), apiToken: jiraApiToken.trim(), projectKey: jiraProjectKey.trim() }
          : { provider, apiKey: linearApiKey.trim(), teamId: linearTeamId.trim() };

      const res = await fetch("/api/account/ticket-integration", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const responseBody = await res.json();
      if (!res.ok) throw new Error(responseBody.error ?? "Could not save ticket integration");
      setMessage(`Connected to ${provider === "jira" ? "Jira" : "Linear"} — a "Create ticket" button now appears on scan findings.`);
      setJiraApiToken("");
      setLinearApiKey("");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function disconnect(p: Provider) {
    setError(null);
    const token = await withToken();
    if (!token) return;
    setBusy(true);
    try {
      const res = await fetch("/api/account/ticket-integration", {
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
        Ticket integration <span className="font-normal text-cybertext/40">(create Jira/Linear issues from findings)</span>
      </summary>
      <div className="px-5 pb-5 pt-1 space-y-4">
        {loading ? (
          <p className="font-mono text-xs text-cybertext/30">// loading…</p>
        ) : status ? (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-cyberborder p-3">
              <div className="text-sm text-cybertext/70">
                Connected to <span className="font-semibold text-neon">{status.provider === "jira" ? "Jira" : "Linear"}</span>
                {status.provider === "jira" && status.jira_project_key && (
                  <span className="text-cybertext/40"> — project {status.jira_project_key}</span>
                )}
              </div>
              <button
                onClick={() => disconnect(status.provider)}
                disabled={busy}
                className="text-xs text-cybertext/40 hover:text-red-400 disabled:opacity-40 transition-colors"
              >
                Disconnect
              </button>
            </div>

            <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-cyberborder p-3">
              <input
                type="checkbox"
                checked={Boolean(status.auto_close_enabled)}
                disabled={busy}
                onChange={(e) => setAutoClose(e.target.checked)}
                className="mt-0.5 h-4 w-4 flex-shrink-0 accent-neon"
              />
              <span className="text-sm text-cybertext/70">
                Close tickets automatically when fixed
                <span className="mt-0.5 block text-xs text-cybertext/40">
                  When a later scan of the same site no longer finds the issue, we move its ticket to your
                  workflow&apos;s done status and add a comment saying when it was verified. Off by default —
                  nothing in {status.provider === "jira" ? "Jira" : "Linear"} moves unless you turn this on.
                </span>
              </span>
            </label>
          </div>
        ) : (
          <>
            <p className="text-sm text-cybertext/60">
              Connect Jira or Linear so any finding can be turned into a real ticket with one click, instead of
              copying remediation text by hand.
            </p>

            <div className="flex gap-2">
              {(["jira", "linear"] as const).map((p) => (
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
                  {p === "jira" ? "Jira" : "Linear"}
                </button>
              ))}
            </div>

            <form onSubmit={save} className="space-y-2">
              {provider === "jira" ? (
                <>
                  <input
                    type="url"
                    required
                    placeholder="https://yourteam.atlassian.net"
                    value={jiraBaseUrl}
                    onChange={(e) => setJiraBaseUrl(e.target.value)}
                    className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
                  />
                  <input
                    type="email"
                    required
                    placeholder="you@company.com (Atlassian account email)"
                    value={jiraEmail}
                    onChange={(e) => setJiraEmail(e.target.value)}
                    className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
                  />
                  <input
                    type="password"
                    required
                    placeholder="API token (id.atlassian.com/manage-profile/security/api-tokens)"
                    value={jiraApiToken}
                    onChange={(e) => setJiraApiToken(e.target.value)}
                    className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
                  />
                  <input
                    type="text"
                    required
                    placeholder="Project key (e.g. SEC)"
                    value={jiraProjectKey}
                    onChange={(e) => setJiraProjectKey(e.target.value)}
                    className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
                  />
                </>
              ) : (
                <>
                  <input
                    type="password"
                    required
                    placeholder="Linear API key (linear.app/settings/api)"
                    value={linearApiKey}
                    onChange={(e) => setLinearApiKey(e.target.value)}
                    className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
                  />
                  <input
                    type="text"
                    required
                    placeholder="Team id"
                    value={linearTeamId}
                    onChange={(e) => setLinearTeamId(e.target.value)}
                    className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
                  />
                </>
              )}
              <button
                disabled={busy}
                className="rounded-md bg-neon px-4 py-2.5 text-sm font-semibold text-cyberbg hover:opacity-90 disabled:opacity-50 shadow-glowsm transition-opacity"
              >
                {busy ? "Connecting…" : "Connect"}
              </button>
            </form>
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

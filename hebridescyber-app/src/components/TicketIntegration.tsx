"use client";

// Connect one issue tracker (Jira, Linear, ServiceNow or GitHub Issues) so a
// finding can become a ticket in one click. Status comes from
// GET /api/account/ticket-integration, which returns a summary with no
// credentials in it — this component never reads ticket_integrations
// directly, so it can't accidentally request a secret column.

import { useCallback, useEffect, useState } from "react";
import { getSession } from "@/lib/auth";
import { TICKET_PROVIDER_LABELS, TICKET_PROVIDERS, type TicketProvider } from "@/lib/ticketProviderList";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardTitle } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { SegmentedControl } from "@/components/ui/segmented-control";

type Summary = { provider: TicketProvider; destination: string | null; autoCloseEnabled: boolean };

type FieldSpec = {
  name: string;
  label: string;
  type: "url" | "email" | "text" | "password";
  placeholder?: string;
  help?: string;
};

const FIELDS: Record<TicketProvider, FieldSpec[]> = {
  jira: [
    { name: "baseUrl", label: "Jira site URL", type: "url", placeholder: "https://yourteam.atlassian.net" },
    { name: "email", label: "Atlassian account email", type: "email", placeholder: "you@company.com" },
    { name: "apiToken", label: "API token", type: "password", help: "Create one at id.atlassian.com → Security → API tokens." },
    { name: "projectKey", label: "Project key", type: "text", placeholder: "SEC" },
  ],
  linear: [
    { name: "apiKey", label: "API key", type: "password", help: "linear.app → Settings → API → Personal API keys." },
    { name: "teamId", label: "Team ID", type: "text" },
  ],
  servicenow: [
    { name: "instanceUrl", label: "Instance URL", type: "url", placeholder: "https://acme.service-now.com" },
    { name: "username", label: "Integration username", type: "text" },
    { name: "password", label: "Password", type: "password", help: "Use a dedicated integration user that can create and update incidents." },
  ],
  github: [
    { name: "repository", label: "Repository", type: "text", placeholder: "owner/repo" },
    { name: "token", label: "Access token", type: "password", help: "A fine-grained token with Issues: read and write on this repository." },
  ],
};

async function authedFetch(input: string, init: RequestInit = {}) {
  const session = await getSession();
  if (!session) throw new Error("Your session has expired — sign in again.");
  const res = await fetch(input, {
    ...init,
    headers: { ...(init.headers ?? {}), Authorization: `Bearer ${session.access_token}`, "Content-Type": "application/json" },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error ?? `Request failed (${res.status})`);
  return body;
}

export default function TicketIntegration() {
  const [status, setStatus] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(true);
  const [provider, setProvider] = useState<TicketProvider>("jira");
  const [values, setValues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const body = await authedFetch("/api/account/ticket-integration");
      setStatus((body.integration as Summary | null) ?? null);
    } catch (err) {
      setResult({ ok: false, text: (err as Error).message });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    authedFetch("/api/account/ticket-integration")
      .then((body) => {
        if (!cancelled) setStatus((body.integration as Summary | null) ?? null);
      })
      .catch((err) => {
        if (!cancelled) setResult({ ok: false, text: (err as Error).message });
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function run(action: () => Promise<string>) {
    setBusy(true);
    setResult(null);
    try {
      const text = await action();
      setResult({ ok: true, text });
      await load();
    } catch (err) {
      setResult({ ok: false, text: (err as Error).message });
    } finally {
      setBusy(false);
    }
  }

  function connect(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = Object.fromEntries(Object.entries(values).map(([k, v]) => [k, v.trim()]));
    let payload: Record<string, string> = { provider, ...trimmed };
    if (provider === "github") {
      const [owner = "", repo = ""] = (trimmed.repository ?? "").split("/");
      payload = { provider, owner, repo, token: trimmed.token ?? "" };
    }
    void run(async () => {
      await authedFetch("/api/account/ticket-integration", { method: "POST", body: JSON.stringify(payload) });
      setValues({});
      return `Connected to ${TICKET_PROVIDER_LABELS[provider]} — a "Create ticket" button now appears on scan findings.`;
    });
  }

  function disconnect(p: TicketProvider) {
    void run(async () => {
      await authedFetch("/api/account/ticket-integration", { method: "DELETE", body: JSON.stringify({ provider: p }) });
      return `Disconnected ${TICKET_PROVIDER_LABELS[p]}.`;
    });
  }

  function setAutoClose(p: TicketProvider, enabled: boolean) {
    void run(async () => {
      await authedFetch("/api/account/ticket-integration", { method: "PATCH", body: JSON.stringify({ provider: p, autoCloseEnabled: enabled }) });
      return enabled
        ? "Auto-close on. Tickets close automatically once a later scan confirms the finding is gone."
        : "Auto-close off. Tickets stay open until you close them yourself.";
    });
  }

  return (
    <Card>
      <CardTitle>ticket integration</CardTitle>
      <CardDescription className="mb-4 mt-1">
        Turn any finding into a ticket in your tracker with one click, instead of copying remediation text by hand.
      </CardDescription>

      {loading ? (
        <p className="font-mono text-xs text-cybermuted" role="status">
          // loading…
        </p>
      ) : status ? (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-cyberborder p-3">
            <p className="text-sm text-cybertext">
              Connected to <span className="font-semibold text-neon">{TICKET_PROVIDER_LABELS[status.provider]}</span>
              {status.destination && <span className="text-cybermuted"> — {status.destination}</span>}
            </p>
            <Button variant="ghost" size="sm" onClick={() => disconnect(status.provider)} disabled={busy}>
              Disconnect
            </Button>
          </div>

          <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-cyberborder p-3">
            <input
              type="checkbox"
              checked={status.autoCloseEnabled}
              disabled={busy}
              onChange={(e) => setAutoClose(status.provider, e.target.checked)}
              className="mt-0.5 h-4 w-4 flex-shrink-0 accent-neon"
            />
            <span className="text-sm text-cybertext">
              Close tickets automatically when fixed
              <span className="mt-0.5 block text-xs text-cybermuted">
                When a later scan of the same site no longer finds the issue, we close its ticket and note when it was
                verified. Off by default — nothing in {TICKET_PROVIDER_LABELS[status.provider]} changes unless you turn
                this on.
              </span>
            </span>
          </label>
        </div>
      ) : (
        <div className="space-y-4">
          <SegmentedControl
            aria-label="Choose a tracker"
            value={provider}
            onChange={(p) => {
              setProvider(p);
              setValues({});
              setResult(null);
            }}
            options={TICKET_PROVIDERS.map((p) => ({ value: p, label: TICKET_PROVIDER_LABELS[p] }))}
          />

          <form onSubmit={connect} className="space-y-3">
            {FIELDS[provider].map((field) => {
              const id = `ticket-${provider}-${field.name}`;
              return (
                <div key={id} className="space-y-1.5">
                  <Label htmlFor={id}>{field.label}</Label>
                  <Input
                    id={id}
                    type={field.type}
                    required
                    placeholder={field.placeholder}
                    autoComplete={field.type === "password" ? "off" : undefined}
                    value={values[field.name] ?? ""}
                    onChange={(e) => setValues((v) => ({ ...v, [field.name]: e.target.value }))}
                    aria-describedby={field.help ? `${id}-help` : undefined}
                  />
                  {field.help && (
                    <p id={`${id}-help`} className="text-xs text-cybermuted">
                      {field.help}
                    </p>
                  )}
                </div>
              );
            })}
            <Button type="submit" disabled={busy}>
              {busy ? "Connecting…" : `Connect ${TICKET_PROVIDER_LABELS[provider]}`}
            </Button>
          </form>
        </div>
      )}

      {result && (
        <Alert variant={result.ok ? "success" : "danger"} className="mt-4">
          {result.text}
        </Alert>
      )}
    </Card>
  );
}

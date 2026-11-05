"use client";

// Microsoft 365 / Entra ID posture connection (P1-4; Pro and above, the
// integrations page renders a LockedFeature below that). "Connect" asks
// /api/account/m365-connect for Microsoft's admin-consent URL and sends the
// browser there; Microsoft returns to /api/account/m365-callback, which lands
// back here with ?m365=<outcome>. We keep the tenant ID only — no password,
// token or secret of the customer's is ever stored.
import { useCallback, useEffect, useState } from "react";
import { getSession } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert } from "@/components/ui/alert";

type Status = {
  configured: boolean;
  connected: boolean;
  tenantId: string | null;
  consentedAt: string | null;
  lastCheckedAt: string | null;
};

const OUTCOME_TEXT: Record<string, { variant: "success" | "warning" | "danger"; text: string }> = {
  connected: { variant: "success", text: "Microsoft 365 connected. The next full or Lookout scan will check its settings." },
  declined: { variant: "warning", text: "Consent wasn't granted, so nothing was connected." },
  missing_permissions: { variant: "warning", text: "Consent was granted without every permission the checks need. Ask a Global Administrator to connect again and accept all of them." },
  consent_not_found: { variant: "danger", text: "Microsoft didn't confirm the consent for that tenant. Try connecting again." },
  invalid_state: { variant: "danger", text: "That connection link had expired or was opened in a different browser. Start again from this page." },
  invalid_tenant: { variant: "danger", text: "Microsoft returned an unexpected tenant. Nothing was connected." },
  not_configured: { variant: "danger", text: "Microsoft 365 checks aren't set up on this deployment yet." },
  rate_limited: { variant: "warning", text: "Too many attempts. Wait a few minutes and try again." },
  error: { variant: "danger", text: "Something went wrong saving the connection. Try again." },
};

function formatDate(iso: string | null): string | null {
  return iso ? new Date(iso).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" }) : null;
}

export default function M365Config() {
  const [status, setStatus] = useState<Status | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<string | null>(null);

  const authHeader = useCallback(async (): Promise<Record<string, string> | null> => {
    const session = await getSession();
    return session ? { Authorization: `Bearer ${session.access_token}` } : null;
  }, []);

  const load = useCallback(async () => {
    const headers = await authHeader();
    if (!headers) return setError("Not signed in.");
    const res = await fetch("/api/account/m365-connect", { headers });
    if (!res.ok) return setError("Couldn't load the Microsoft 365 connection.");
    setStatus((await res.json()) as Status);
  }, [authHeader]);

  useEffect(() => {
    const value = new URLSearchParams(window.location.search).get("m365");
    // eslint-disable-next-line react-hooks/set-state-in-effect -- read once from the callback's redirect
    if (value && value in OUTCOME_TEXT) setOutcome(value);
    void load();
  }, [load]);

  async function connect() {
    setBusy(true);
    setError(null);
    try {
      const headers = await authHeader();
      if (!headers) return setError("Not signed in.");
      const res = await fetch("/api/account/m365-connect", { method: "POST", headers });
      const body = (await res.json().catch(() => ({}))) as { url?: string; error?: string };
      if (!res.ok || !body.url) return setError(body.error ?? "Couldn't start the connection.");
      window.location.assign(body.url);
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    setBusy(true);
    setError(null);
    try {
      const headers = await authHeader();
      if (!headers) return setError("Not signed in.");
      const res = await fetch("/api/account/m365-connect", { method: "DELETE", headers });
      const body = (await res.json().catch(() => ({}))) as { revokeSteps?: string; error?: string };
      if (!res.ok) return setError(body.error ?? "Couldn't disconnect.");
      setOutcome(null);
      setMessage(`Disconnected: we've forgotten the tenant and won't check it again. ${body.revokeSteps ?? ""}`.trim());
      await load();
    } finally {
      setBusy(false);
    }
  }

  const shown = outcome ? OUTCOME_TEXT[outcome] : null;

  return (
    <Card>
      <CardHeader>
        <div className="space-y-1">
          <CardTitle>microsoft 365 &amp; entra id</CardTitle>
          <CardDescription>
            Read-only checks of your tenant: MFA for users and admins, legacy sign-in, Conditional Access, Global Admin count, external mail
            forwarding, guest access, app consent and sign-in logs. A Global Administrator grants consent once; we store your tenant ID only.
          </CardDescription>
        </div>
      </CardHeader>

      <div className="space-y-4">
        {shown && <Alert variant={shown.variant}>{shown.text}</Alert>}
        {message && <Alert variant="success">{message}</Alert>}
        {error && <Alert variant="danger">{error}</Alert>}

        {status && !status.configured && !status.connected && (
          <Alert variant="info">Microsoft 365 checks aren&apos;t available on this deployment yet.</Alert>
        )}

        {status?.connected ? (
          <div className="space-y-3 text-sm text-cybertext">
            <p>
              Connected to tenant <span className="font-mono">{status.tenantId}</span>
              {status.consentedAt && <> since {formatDate(status.consentedAt)}</>}.
            </p>
            <p className="text-cybermuted">{status.lastCheckedAt ? `Last checked ${formatDate(status.lastCheckedAt)}.` : "Not checked yet."}</p>
            <Button variant="danger" onClick={disconnect} disabled={busy}>
              Disconnect
            </Button>
          </div>
        ) : (
          status?.configured && (
            <div className="space-y-2">
              <Button onClick={connect} disabled={busy}>
                Connect Microsoft 365
              </Button>
              <p className="text-xs text-cybermuted">
                You&apos;ll be sent to Microsoft to sign in as a Global Administrator and approve read-only access.
              </p>
            </div>
          )
        )}
      </div>
    </Card>
  );
}

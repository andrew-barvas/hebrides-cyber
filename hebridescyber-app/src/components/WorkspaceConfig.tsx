"use client";

// Google Workspace posture connection (migration 076; Pro and above). Mirrors
// M365Config.tsx: "Connect" asks /api/account/workspace-connect for Google's
// consent URL; Google returns to /api/account/workspace-callback, which lands
// back here with ?workspace=<outcome>. We keep a sealed, read-only refresh
// token; disconnecting revokes it at Google.
import { useCallback, useEffect, useState } from "react";
import { getSession } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert } from "@/components/ui/alert";

type Status = {
  configured: boolean;
  connected: boolean;
  connectedAt: string | null;
  lastCheckedAt: string | null;
};

const OUTCOME_TEXT: Record<string, { variant: "success" | "warning" | "danger"; text: string }> = {
  connected: { variant: "success", text: "Google Workspace connected. The next full or Lookout scan will check its settings." },
  declined: { variant: "warning", text: "Access wasn't granted, so nothing was connected." },
  missing_permissions: { variant: "warning", text: "Access was granted without every permission the checks need. Connect again as a super admin and allow all of them." },
  no_refresh_token: { variant: "warning", text: "Google didn't return lasting access. Remove Hebrides Cyber from your Google account's third-party access, then connect again." },
  invalid_state: { variant: "danger", text: "That connection link had expired or was opened in a different browser. Start again from this page." },
  not_configured: { variant: "danger", text: "Google Workspace checks aren't set up on this deployment yet." },
  rate_limited: { variant: "warning", text: "Too many attempts. Wait a few minutes and try again." },
  error: { variant: "danger", text: "Something went wrong saving the connection. Try again." },
};

function formatDate(iso: string | null): string | null {
  return iso ? new Date(iso).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" }) : null;
}

export default function WorkspaceConfig() {
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
    const res = await fetch("/api/account/workspace-connect", { headers });
    if (!res.ok) return setError("Couldn't load the Google Workspace connection.");
    setStatus((await res.json()) as Status);
  }, [authHeader]);

  useEffect(() => {
    const value = new URLSearchParams(window.location.search).get("workspace");
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
      const res = await fetch("/api/account/workspace-connect", { method: "POST", headers });
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
      const res = await fetch("/api/account/workspace-connect", { method: "DELETE", headers });
      const body = (await res.json().catch(() => ({}))) as { error?: string };
      if (!res.ok) return setError(body.error ?? "Couldn't disconnect.");
      setOutcome(null);
      setMessage("Disconnected: we've revoked our access at Google and deleted the token.");
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
          <CardTitle>google workspace</CardTitle>
          <CardDescription>
            Read-only checks of your Workspace: 2-Step Verification for users and super admins, and how many super admins you have. A super
            admin allows access once; we keep a sealed, read-only token and can be disconnected at any time.
          </CardDescription>
        </div>
      </CardHeader>

      <div className="space-y-4">
        {shown && <Alert variant={shown.variant}>{shown.text}</Alert>}
        {message && <Alert variant="success">{message}</Alert>}
        {error && <Alert variant="danger">{error}</Alert>}

        {status && !status.configured && !status.connected && (
          <Alert variant="info">Google Workspace checks aren&apos;t available on this deployment yet.</Alert>
        )}

        {status?.connected ? (
          <div className="space-y-3 text-sm text-cybertext">
            <p>Connected{status.connectedAt && <> since {formatDate(status.connectedAt)}</>}.</p>
            <p className="text-cybermuted">{status.lastCheckedAt ? `Last checked ${formatDate(status.lastCheckedAt)}.` : "Not checked yet."}</p>
            <Button variant="danger" onClick={disconnect} disabled={busy}>
              Disconnect
            </Button>
          </div>
        ) : (
          status?.configured && (
            <div className="space-y-2">
              <Button onClick={connect} disabled={busy}>
                Connect Google Workspace
              </Button>
              <p className="text-xs text-cybermuted">
                You&apos;ll be sent to Google to sign in as a super admin and allow read-only access.
              </p>
            </div>
          )
        )}
      </div>
    </Card>
  );
}

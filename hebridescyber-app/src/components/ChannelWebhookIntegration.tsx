"use client";

// Slack / Microsoft Teams incoming-webhook settings. Saves through
// POST /api/account/notification-webhooks — the dashboard's previous inline
// forms still wrote straight to `subscriptions` from the browser, which
// 024_subscriptions_lockdown.sql made a silent no-op (no client UPDATE policy
// → zero rows updated, no error), so they reported "Saved" while persisting
// nothing.

import { useState } from "react";
import { getSession } from "@/lib/auth";
import { useAppSession } from "@/components/app-shell/AppShell";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardTitle } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";

type Provider = "slack" | "teams";

const CONFIG: Record<
  Provider,
  { title: string; field: "slackWebhookUrl" | "msTeamsWebhookUrl"; placeholder: string; helpHref: string; helpLabel: string; before: string; after: string }
> = {
  slack: {
    title: "slack alerts",
    field: "slackWebhookUrl",
    placeholder: "https://hooks.slack.com/services/…",
    helpHref: "https://api.slack.com/messaging/webhooks",
    helpLabel: "incoming webhook URL",
    before: "Post scan results to a Slack channel. Paste your",
    after: "below.",
  },
  teams: {
    title: "microsoft teams alerts",
    field: "msTeamsWebhookUrl",
    placeholder: "https://outlook.office.com/webhook/…",
    helpHref: "https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook",
    helpLabel: "incoming webhook",
    before: "Post scan results to a Teams channel. Add an",
    after: "to the channel and paste its URL below. Independent of Slack — set either, both, or neither.",
  },
};

export default function ChannelWebhookIntegration({ provider }: { provider: Provider }) {
  const cfg = CONFIG[provider];
  const { slackWebhookUrl, teamsWebhookUrl, refreshSubscription } = useAppSession();
  const [url, setUrl] = useState(provider === "slack" ? slackWebhookUrl : teamsWebhookUrl);
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  const inputId = `${provider}-webhook-url`;

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setResult(null);
    try {
      const session = await getSession();
      if (!session) throw new Error("Your session has expired — sign in again.");
      const trimmed = url.trim();
      const res = await fetch("/api/account/notification-webhooks", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.access_token}` },
        // null clears it — the route's .url() validation rejects "".
        body: JSON.stringify({ [cfg.field]: trimmed || null }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error ?? `Save failed (${res.status})`);
      setResult({
        ok: true,
        text: trimmed ? "Saved — alerts will post to this channel when scans complete." : "Removed — this channel won't receive alerts.",
      });
      await refreshSubscription();
    } catch (err) {
      setResult({ ok: false, text: (err as Error).message });
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <CardTitle>{cfg.title}</CardTitle>
      <CardDescription className="mb-3 mt-1">
        {cfg.before}{" "}
        <a href={cfg.helpHref} target="_blank" rel="noreferrer" className="text-neon underline hover:text-cybertext">
          {cfg.helpLabel}
        </a>{" "}
        {cfg.after}
      </CardDescription>
      <form onSubmit={save} className="flex flex-col gap-2 sm:flex-row sm:items-end">
        <div className="flex-1 space-y-1.5">
          <Label htmlFor={inputId} className="sr-only">
            {provider === "slack" ? "Slack" : "Microsoft Teams"} webhook URL
          </Label>
          <Input
            id={inputId}
            type="url"
            placeholder={cfg.placeholder}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="font-mono text-xs"
          />
        </div>
        <Button type="submit" variant="secondary" disabled={saving}>
          {saving ? "Saving…" : "Save"}
        </Button>
      </form>
      {result && (
        <Alert variant={result.ok ? "success" : "danger"} className="mt-3">
          {result.text}
        </Alert>
      )}
    </Card>
  );
}

// POST /api/account/notification-webhooks — saves slack_webhook_url/
// ms_teams_webhook_url on the caller's own subscriptions row.
//
// Replaces two raw browser-side `supabase.from("subscriptions").update(...)`
// calls (src/app/dashboard/page.tsx's saveSlackWebhook/saveTeamsWebhook)
// that relied on 002_improvements.sql's now-removed client UPDATE policy —
// see 024_subscriptions_lockdown.sql for why that policy had to go (it
// granted UPDATE on the *entire* row, including plan/status, letting any
// customer self-escalate to a paid plan for free from the browser console).
//
// This route never reads plan/status from the request body at all — there
// is no code path here, client-supplied or otherwise, that can set those
// two columns to anything. The only place that still sets them is
// src/pages/api/stripe/webhook.ts's own upsert.
//
// The one exception: an admin account with NO subscriptions row yet
// (never went through Stripe checkout, since admin access doesn't require
// a paid plan) has nowhere to store a webhook URL — plan is NOT NULL with
// no default, so a row can't exist without one. For an admin ONLY, this
// route creates one with a fixed default (agency/active) so the account
// has somewhere to persist the setting; this is not a new privilege for
// that account (an admin already has full system access via the admin
// panel) and is gated on the server-verified users.is_admin flag, never on
// anything the client sends.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { isValidSlackWebhookUrl, isValidTeamsWebhookUrl } from "@/lib/webhookUrlValidation";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Notification webhooks can only be managed from a logged-in session, not with an API key." });
  }

  const { slackWebhookUrl, msTeamsWebhookUrl } = req.body as { slackWebhookUrl?: string | null; msTeamsWebhookUrl?: string | null };

  // Defense in depth, not the primary control — a bare "starts with
  // https://" check here was previously trivially satisfiable by any
  // attacker-controlled endpoint, since these fields fan out to a real
  // outbound fetch() on every scan completion (src/lib/slack.ts,
  // src/lib/msTeams.ts). Those two files now enforce the same allowlist at
  // the actual fetch call site, which is what actually matters; this check
  // just gives the customer an immediate error instead of a silently
  // dropped alert later.
  if (slackWebhookUrl && !isValidSlackWebhookUrl(slackWebhookUrl)) {
    return res.status(400).json({ error: "slackWebhookUrl must be a hooks.slack.com https:// URL" });
  }
  if (msTeamsWebhookUrl && !isValidTeamsWebhookUrl(msTeamsWebhookUrl)) {
    return res.status(400).json({ error: "msTeamsWebhookUrl must be a Microsoft Teams webhook https:// URL" });
  }

  const { data: user } = await supabaseAdmin.from("users").select("is_admin").eq("id", caller.ownerId).maybeSingle();
  const isAdmin = Boolean(user?.is_admin);

  const { data: existing } = await supabaseAdmin
    .from("subscriptions")
    .select("owner")
    .eq("owner", caller.ownerId)
    .maybeSingle();

  const webhookFields = {
    ...(slackWebhookUrl !== undefined && { slack_webhook_url: slackWebhookUrl || null }),
    ...(msTeamsWebhookUrl !== undefined && { ms_teams_webhook_url: msTeamsWebhookUrl || null }),
  };

  if (!existing) {
    if (!isAdmin) {
      return res.status(409).json({ error: "An active subscription is required before configuring alert webhooks." });
    }
    // Admin-only bootstrap row — see module header. Fixed values, never
    // read from the request body.
    const { error } = await supabaseAdmin.from("subscriptions").insert({
      owner: caller.ownerId,
      plan: "agency",
      status: "active",
      ...webhookFields,
    });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  const { error } = await supabaseAdmin.from("subscriptions").update(webhookFields).eq("owner", caller.ownerId);
  if (error) return res.status(500).json({ error: error.message });
  return res.status(200).json({ ok: true });
}

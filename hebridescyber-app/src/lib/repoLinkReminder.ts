// One email per owner whose connected repositories aren't linked to a site
// (next-10 task 9). Since migration 077 an unlinked repository is never
// scanned, so its code checks stopped silently; this tells the owner once
// and points them at Integrations. Each connection is reminded at most once
// (repo_connections.link_reminder_sent_at, migration 080).
import type { SupabaseClient } from "@supabase/supabase-js";
import { escapeHtml, sendEmail } from "./email";

type Row = { id: string; owner: string; github_repo: string };
export type ReminderResult = { sent: number; skipped: number; errors: string[] };

/** Pure: rows → owner → their unlinked repositories. */
export function groupByOwner(rows: readonly Row[]): Map<string, Row[]> {
  const out = new Map<string, Row[]>();
  for (const r of rows) out.set(r.owner, [...(out.get(r.owner) ?? []), r]);
  return out;
}

/** Pure. */
export function buildReminderEmail(repos: string[], siteUrl: string): { subject: string; html: string } {
  const list = repos.map((r) => `<li><code>${escapeHtml(r)}</code></li>`).join("");
  const one = repos.length === 1;
  return {
    subject: one ? "Your repository's code checks are paused: choose its site" : "Your repositories' code checks are paused: choose their sites",
    html: `
    <div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:600px;margin:0 auto;color:#111827;font-size:14px;line-height:1.5;">
      <p>We've changed how connected repositories work: each one is now checked only on scans of the site it belongs to, so its results can never land on the wrong site.</p>
      <p>${one ? "This repository isn't" : "These repositories aren't"} linked to a site yet, so ${one ? "its" : "their"} code checks (secrets, dependencies, code scanning) are paused:</p>
      <ul>${list}</ul>
      <p><a href="${siteUrl}/dashboard/integrations#connect-repo" style="display:inline-block;background:#0b3d5b;color:#ffffff;text-decoration:none;padding:10px 16px;border-radius:6px;">Choose ${one ? "its site" : "their sites"}</a></p>
      <p style="color:#6b7280;font-size:12px;">It takes a few seconds: pick the site next to each repository and click Link. We'll only send this once.</p>
    </div>`,
  };
}

export async function sendRepoLinkReminders(supabaseAdmin: SupabaseClient, opts: { now?: Date; siteUrl?: string; dryRun?: boolean } = {}): Promise<ReminderResult> {
  const now = (opts.now ?? new Date()).toISOString();
  const siteUrl = opts.siteUrl ?? process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
  const { data, error } = await supabaseAdmin.from("repo_connections").select("id, owner, github_repo").is("target_host", null).is("link_reminder_sent_at", null);
  if (error) throw new Error(error.message);
  const result: ReminderResult = { sent: 0, skipped: 0, errors: [] };
  for (const [owner, rows] of groupByOwner((data ?? []) as Row[])) {
    try {
      const { data: user } = await supabaseAdmin.from("users").select("email").eq("id", owner).maybeSingle();
      const to = (user as { email?: string } | null)?.email;
      if (!to) {
        result.skipped++;
        continue;
      }
      if (opts.dryRun) {
        console.log(`would remind ${owner} about ${rows.map((r) => r.github_repo).join(", ")}`);
        result.skipped++;
        continue;
      }
      const email = buildReminderEmail(rows.map((r) => r.github_repo), siteUrl);
      const sent = await sendEmail({ to, subject: email.subject, html: email.html });
      if (!sent.ok) throw new Error(sent.error ?? "send failed");
      const { error: markError } = await supabaseAdmin.from("repo_connections").update({ link_reminder_sent_at: now }).in("id", rows.map((r) => r.id));
      if (markError) throw new Error(`sent, but couldn't record it: ${markError.message}`);
      result.sent++;
    } catch (err) {
      result.errors.push(`${owner}: ${(err as Error).message}`);
    }
  }
  return result;
}

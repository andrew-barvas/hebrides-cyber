// Email deliverability events. sendEmail() records one row per real send
// attempt (migration 056) so the admin "Email" view can show a recent send
// count and failure rate — the shared Resend sender is otherwise best-effort
// and its failures were only console.error'd. The recording never affects
// whether an email is considered sent.
import type { SupabaseClient } from "@supabase/supabase-js";

/** First recipient's domain only — PII-minimised (never the full address). */
export function recipientDomain(to: string | string[]): string | null {
  const first = Array.isArray(to) ? to[0] : to;
  if (!first) return null;
  const at = first.lastIndexOf("@");
  return at >= 0 && at < first.length - 1 ? first.slice(at + 1).toLowerCase() : null;
}

export type EmailEventInput = {
  to: string | string[];
  subject: string;
  status: "sent" | "failed";
  error?: string;
};

/**
 * Best-effort insert of one send outcome. Never throws and never blocks the
 * caller on a DB problem — a missing table (pre-056) or any write error is
 * swallowed, because losing a monitoring row must never turn into a failed
 * email or a failed cron run.
 */
export async function recordEmailOutcome(db: SupabaseClient, input: EmailEventInput): Promise<void> {
  try {
    await db.from("email_events").insert({
      recipient_domain: recipientDomain(input.to),
      subject: input.subject.slice(0, 300),
      status: input.status,
      error: input.error ? input.error.slice(0, 500) : null,
    });
  } catch {
    // monitoring is strictly best-effort
  }
}

export type EmailEventRow = { status: "sent" | "failed"; subject: string | null; recipient_domain: string | null; error: string | null; created_at: string };

export type EmailHealth = {
  windowHours: number;
  total: number;
  sent: number;
  failed: number;
  failureRatePct: number | null;
  recentFailures: { subject: string | null; domain: string | null; error: string | null; at: string }[];
};

/**
 * Pure summary of recent email events over a trailing window. failureRatePct
 * is null (not 0) when nothing was sent in the window — no sends is "no data",
 * not "0% failure". recentFailures lists the latest failed sends (newest
 * first), capped, so the admin sees what's actually bouncing.
 */
export function summarizeEmailHealth(rows: EmailEventRow[], now: Date, windowHours = 24): EmailHealth {
  const cutoff = now.getTime() - windowHours * 3_600_000;
  const inWindow = rows.filter((r) => Date.parse(r.created_at) >= cutoff);
  const failedRows = inWindow
    .filter((r) => r.status === "failed")
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  const total = inWindow.length;
  const failed = failedRows.length;
  const sent = total - failed;
  return {
    windowHours,
    total,
    sent,
    failed,
    failureRatePct: total === 0 ? null : (failed / total) * 100,
    recentFailures: failedRows.slice(0, 10).map((r) => ({ subject: r.subject, domain: r.recipient_domain, error: r.error, at: r.created_at })),
  };
}

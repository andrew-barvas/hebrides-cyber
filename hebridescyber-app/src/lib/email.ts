// Shared Resend-sending helper. Extracted from src/pages/api/contact.ts (the
// only place that sent email before this file existed) so other code —
// scan alert emails (src/lib/scanAlerts.ts) and the monthly digest
// (src/pages/api/send-monthly-digest.ts) — can send email without each
// re-implementing the same fetch-to-Resend plumbing.
//
// Never throws: an email failure must never crash the scan pipeline or a
// cron job that happens to trigger it. Callers get back { ok, error } and
// decide for themselves whether/how to log it.
/** A file sent with the email (a scheduled report's PDF). */
export type EmailAttachment = { filename: string; content: Buffer };

export type SendEmailInput = {
  to: string | string[];
  subject: string;
  html: string;
  /** Defaults to the shared sender identity used by the contact form. */
  from?: string;
  attachments?: EmailAttachment[];
};

export type SendEmailResult = { ok: boolean; error?: string };

const DEFAULT_FROM = "Hebrides Cyber <noreply@hebridescyber.co.uk>";

/**
 * Best-effort deliverability recording (migration 056). Only runs when the
 * service-role env is present (so it no-ops in tests and local dev), lazily
 * acquires the client, and swallows everything — a monitoring write must
 * never affect whether the email counts as sent.
 */
async function recordOutcome(to: string | string[], subject: string, result: SendEmailResult): Promise<void> {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) return;
  try {
    const { getSupabaseAdmin } = await import("./supabaseAdmin");
    const { recordEmailOutcome } = await import("./emailEvents");
    await recordEmailOutcome(getSupabaseAdmin(), {
      to,
      subject,
      status: result.ok ? "sent" : "failed",
      error: result.error,
    });
  } catch {
    // strictly best-effort
  }
}

/**
 * Sends one email via Resend (https://resend.com). Set RESEND_API_KEY to
 * enable — resolves to { ok: false } (not a throw) when unset, matching
 * how contact.ts previously skipped sending silently when unconfigured.
 */
export async function sendEmail({ to, subject, html, from = DEFAULT_FROM, attachments }: SendEmailInput): Promise<SendEmailResult> {
  const resendKey = process.env.RESEND_API_KEY;
  // Not a real attempt (no provider configured) — don't record it as a
  // deliverability failure, that would drown real bounces in noise.
  if (!resendKey) return { ok: false, error: "RESEND_API_KEY not configured" };

  let result: SendEmailResult;
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${resendKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from,
        to: Array.isArray(to) ? to : [to],
        subject,
        html,
        // Resend's JSON API takes attachment bytes base64-encoded.
        ...(attachments?.length
          ? { attachments: attachments.map((a) => ({ filename: a.filename, content: a.content.toString("base64") })) }
          : {}),
      }),
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      result = { ok: false, error: `Resend responded ${res.status}: ${text}` };
    } else {
      result = { ok: true };
    }
  } catch (err) {
    result = { ok: false, error: (err as Error).message };
  }

  await recordOutcome(to, subject, result);
  return result;
}

/** HTML-escaping helper, matching the inline version that lived in contact.ts. */
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

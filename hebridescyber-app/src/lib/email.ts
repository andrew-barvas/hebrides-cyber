// Shared Resend-sending helper. Extracted from src/pages/api/contact.ts (the
// only place that sent email before this file existed) so other code —
// scan alert emails (src/lib/scanAlerts.ts) and the monthly digest
// (src/pages/api/send-monthly-digest.ts) — can send email without each
// re-implementing the same fetch-to-Resend plumbing.
//
// Never throws: an email failure must never crash the scan pipeline or a
// cron job that happens to trigger it. Callers get back { ok, error } and
// decide for themselves whether/how to log it.
export type SendEmailInput = {
  to: string | string[];
  subject: string;
  html: string;
  /** Defaults to the shared sender identity used by the contact form. */
  from?: string;
};

export type SendEmailResult = { ok: boolean; error?: string };

const DEFAULT_FROM = "Hebrides Cyber <noreply@hebridescyber.com>";

/**
 * Sends one email via Resend (https://resend.com). Set RESEND_API_KEY to
 * enable — resolves to { ok: false } (not a throw) when unset, matching
 * how contact.ts previously skipped sending silently when unconfigured.
 */
export async function sendEmail({ to, subject, html, from = DEFAULT_FROM }: SendEmailInput): Promise<SendEmailResult> {
  const resendKey = process.env.RESEND_API_KEY;
  if (!resendKey) return { ok: false, error: "RESEND_API_KEY not configured" };

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
      }),
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      return { ok: false, error: `Resend responded ${res.status}: ${text}` };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

/** HTML-escaping helper, matching the inline version that lived in contact.ts. */
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

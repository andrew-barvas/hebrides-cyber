import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/supabaseAdmin";
import { sendEmail, escapeHtml } from "@/lib/email";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";

// E-05 (docs/ENHANCEMENTS.md): this was the only fully-open, unauthenticated
// write path in the app with zero abuse protection. Keyed by IP (no
// ownerId exists pre-auth) under its own "contact" namespace so it can't
// share a bucket with run-scan.ts/v1/scans.ts's owner-keyed scan-creation
// limit — see rateLimit.ts's namespace comment.
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const limit = await checkRateLimit(getClientIp(req), "contact");
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many messages sent — please try again later." });
  }

  const { name, email, url, message } = req.body as Record<string, unknown>;

  if (!name || typeof name !== "string" || name.trim().length < 2)
    return res.status(400).json({ error: "Please enter your name." });
  if (!email || typeof email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: "Please enter a valid email address." });
  if (!message || typeof message !== "string" || message.trim().length < 10)
    return res.status(400).json({ error: "Please write a message (10+ characters)." });
  if (url && typeof url === "string" && url.trim().length > 0) {
    try { new URL(url.trim()); } catch {
      return res.status(400).json({ error: "Please enter a valid URL, or leave it blank." });
    }
  }

  // supabaseAdmin's client is constructed lazily on first access, so a
  // missing SUPABASE_URL/SERVICE_ROLE_KEY throws here rather than at import —
  // caught below and folded into the same "failed to save" response used for
  // an ordinary insert error, rather than an unhandled 500.
  try {
    const { error: insertError } = await supabaseAdmin.from("contact_enquiries").insert({
      name: name.trim(),
      email: email.trim().toLowerCase(),
      url: typeof url === "string" && url.trim() ? url.trim() : null,
      message: message.trim(),
    });

    if (insertError) throw new Error(insertError.message);
  } catch (err) {
    console.error("[contact] insert error:", (err as Error).message);
    return res.status(500).json({ error: "Failed to save your message — please try again." });
  }

  // Send a notification email via Resend if configured.
  // Set RESEND_API_KEY and CONTACT_EMAIL in environment variables.
  // sendEmail() never throws and resolves { ok: false } when RESEND_API_KEY
  // is unset, so this stays non-fatal exactly as the inline fetch was.
  const toEmail = process.env.CONTACT_EMAIL ?? "hello@hebridescyber.co.uk";
  const result = await sendEmail({
    to: toEmail,
    subject: `New enquiry from ${name.trim()}`,
    html: [
      `<p><strong>Name:</strong> ${escapeHtml(name.trim())}</p>`,
      `<p><strong>Email:</strong> ${escapeHtml(email.trim())}</p>`,
      typeof url === "string" && url.trim()
        ? `<p><strong>Website:</strong> ${escapeHtml(url.trim())}</p>`
        : "",
      `<p><strong>Message:</strong></p>`,
      `<p>${escapeHtml(message.trim()).replace(/\n/g, "<br>")}</p>`,
    ].join(""),
  });
  if (!result.ok && result.error !== "RESEND_API_KEY not configured") {
    // Non-fatal: the record is saved; log but don't fail the request.
    console.error("[contact] Resend error:", result.error);
  }

  return res.status(200).json({ ok: true });
}

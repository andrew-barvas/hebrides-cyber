import type { NextApiRequest, NextApiResponse } from "next";
import { createClient } from "@supabase/supabase-js";

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

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

  const { error: insertError } = await supabaseAdmin.from("contact_enquiries").insert({
    name: name.trim(),
    email: email.trim().toLowerCase(),
    url: typeof url === "string" && url.trim() ? url.trim() : null,
    message: message.trim(),
  });

  if (insertError) {
    console.error("[contact] insert error:", insertError.message);
    return res.status(500).json({ error: "Failed to save your message — please try again." });
  }

  // Send a notification email via Resend if configured.
  // Set RESEND_API_KEY and CONTACT_EMAIL in environment variables.
  const resendKey = process.env.RESEND_API_KEY;
  const toEmail = process.env.CONTACT_EMAIL ?? "hello@hebridescyber.com";
  if (resendKey) {
    try {
      await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${resendKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: "Hebrides Cyber <noreply@hebridescyber.com>",
          to: [toEmail],
          subject: `New enquiry from ${name.trim()}`,
          html: [
            `<p><strong>Name:</strong> ${escape(name.trim())}</p>`,
            `<p><strong>Email:</strong> ${escape(email.trim())}</p>`,
            typeof url === "string" && url.trim()
              ? `<p><strong>Website:</strong> ${escape(url.trim())}</p>`
              : "",
            `<p><strong>Message:</strong></p>`,
            `<p>${escape(message.trim()).replace(/\n/g, "<br>")}</p>`,
          ].join(""),
        }),
      });
    } catch (emailErr) {
      // Non-fatal: the record is saved; log but don't fail the request.
      console.error("[contact] Resend error:", (emailErr as Error).message);
    }
  }

  return res.status(200).json({ ok: true });
}

function escape(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

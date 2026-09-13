import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { supabaseAdmin } from "@/lib/supabaseAdmin";
import { sendEmail, escapeHtml } from "@/lib/email";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";
import { isTeamSize, isBudgetRange, teamSizeLabel, budgetRangeLabel } from "@/lib/contactOptions";
import { parseBody } from "@/lib/validate";

const TEAM_SIZE_VALUES = ["solo", "2_10", "11_50", "51_200", "200_plus"] as const;
const BUDGET_RANGE_VALUES = ["unsure", "under_300", "300_800", "800_1800", "1800_plus"] as const;

const bodySchema = z.object({
  name: z.string().min(2, "Please enter your name."),
  email: z.string().email("Please enter a valid email address."),
  message: z.string().min(10, "Please write a message (10+ characters)."),
  url: z.string().url("Please enter a valid URL, or leave it blank.").optional().or(z.literal("")),
  company: z.string().optional().or(z.literal("")),
  teamSize: z.enum(TEAM_SIZE_VALUES).optional().or(z.literal("")),
  budgetRange: z.enum(BUDGET_RANGE_VALUES).optional().or(z.literal("")),
});

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

  const parsed = parseBody(bodySchema, req.body, res);
  if (!parsed) return;
  const { name, email, url, message, company, teamSize, budgetRange } = parsed;

  // supabaseAdmin's client is constructed lazily on first access, so a
  // missing SUPABASE_URL/SERVICE_ROLE_KEY throws here rather than at import —
  // caught below and folded into the same "failed to save" response used for
  // an ordinary insert error, rather than an unhandled 500.
  try {
    const { error: insertError } = await supabaseAdmin.from("contact_enquiries").insert({
      name: name.trim(),
      email: email.trim().toLowerCase(),
      url: url && url.trim() ? url.trim() : null,
      message: message.trim(),
      company: company && company.trim() ? company.trim() : null,
      team_size: teamSize && isTeamSize(teamSize) ? teamSize : null,
      budget_range: budgetRange && isBudgetRange(budgetRange) ? budgetRange : null,
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
  // Budget surfaced in the subject line (when answered and not "unsure") so
  // a high-budget lead is visible from an inbox/notification preview
  // without opening the email at all.
  const budgetSubjectSuffix =
    budgetRange && isBudgetRange(budgetRange) && budgetRange !== "unsure" ? ` — budget ${budgetRangeLabel(budgetRange)}` : "";
  const result = await sendEmail({
    to: toEmail,
    subject: `New enquiry from ${name.trim()}${budgetSubjectSuffix}`,
    html: [
      `<p><strong>Name:</strong> ${escapeHtml(name.trim())}</p>`,
      `<p><strong>Email:</strong> ${escapeHtml(email.trim())}</p>`,
      url && url.trim()
        ? `<p><strong>Website:</strong> ${escapeHtml(url.trim())}</p>`
        : "",
      company && company.trim()
        ? `<p><strong>Company:</strong> ${escapeHtml(company.trim())}</p>`
        : "",
      teamSize && isTeamSize(teamSize) ? `<p><strong>Team size:</strong> ${escapeHtml(teamSizeLabel(teamSize) ?? teamSize)}</p>` : "",
      budgetRange && isBudgetRange(budgetRange) ? `<p><strong>Budget:</strong> ${escapeHtml(budgetRangeLabel(budgetRange) ?? budgetRange)}</p>` : "",
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

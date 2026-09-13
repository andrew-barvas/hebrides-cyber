// POST /api/account/request-audit — lets a logged-in user request one of the
// three one-off audit tiers (src/lib/auditTiers.ts) from the dashboard,
// instead of leaving the app to fill in the public /contact form. Reuses
// that same pipeline rather than inventing a second one: it writes an
// ordinary contact_enquiries row (so it shows up in the existing admin
// enquiries view, src/app/admin/page.tsx) and sends the same notification
// email contact.ts sends, with the requester's account email/company
// pre-filled server-side rather than re-typed.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { sendEmail, escapeHtml } from "@/lib/email";
import { checkRateLimit } from "@/lib/rateLimit";
import { getAuditTier } from "@/lib/auditTiers";
import { parseBody } from "@/lib/validate";

const bodySchema = z.object({
  tier: z.enum(["small", "standard", "full"]),
  targetUrl: z.string().url().optional().or(z.literal("")),
  notes: z.string().optional(),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Audit requests can only be made from a logged-in session, not with an API key." });
  }

  // Authenticated, so keyed by ownerId rather than IP — its own namespace so
  // it can't share a bucket with the public contact form's IP-keyed limit.
  const limit = await checkRateLimit(caller.ownerId, "request-audit");
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many audit requests sent — please try again later." });
  }

  const parsed = parseBody(bodySchema, req.body, res);
  if (!parsed) return;
  const { tier, targetUrl, notes } = parsed;

  const { data: profile } = await supabaseAdmin
    .from("users")
    .select("email, company_name")
    .eq("id", caller.ownerId)
    .maybeSingle();
  if (!profile?.email) return res.status(404).json({ error: "Account profile not found" });

  const auditTier = getAuditTier(tier);
  const trimmedNotes = typeof notes === "string" ? notes.trim() : "";
  const trimmedUrl = typeof targetUrl === "string" ? targetUrl.trim() : "";
  const message = [
    `Requesting: ${auditTier.name} (${auditTier.price}) — submitted from the dashboard.`,
    trimmedNotes ? `Notes: ${trimmedNotes}` : "",
  ]
    .filter(Boolean)
    .join("\n");

  try {
    const { error: insertError } = await supabaseAdmin.from("contact_enquiries").insert({
      name: profile.company_name ?? profile.email,
      email: profile.email,
      url: trimmedUrl || null,
      message,
      company: profile.company_name ?? null,
      team_size: null,
      budget_range: auditTier.budgetRange,
    });
    if (insertError) throw new Error(insertError.message);
  } catch (err) {
    console.error("[request-audit] insert error:", (err as Error).message);
    return res.status(500).json({ error: "Failed to save your request — please try again." });
  }

  const toEmail = process.env.CONTACT_EMAIL ?? "hello@hebridescyber.co.uk";
  const result = await sendEmail({
    to: toEmail,
    subject: `Dashboard audit request: ${auditTier.name} from ${profile.email}`,
    html: [
      `<p><strong>Tier:</strong> ${escapeHtml(auditTier.name)} (${escapeHtml(auditTier.price)})</p>`,
      `<p><strong>Account email:</strong> ${escapeHtml(profile.email)}</p>`,
      profile.company_name ? `<p><strong>Company:</strong> ${escapeHtml(profile.company_name)}</p>` : "",
      trimmedUrl ? `<p><strong>Target URL:</strong> ${escapeHtml(trimmedUrl)}</p>` : "",
      trimmedNotes ? `<p><strong>Notes:</strong></p><p>${escapeHtml(trimmedNotes).replace(/\n/g, "<br>")}</p>` : "",
    ].join(""),
  });
  if (!result.ok && result.error !== "RESEND_API_KEY not configured") {
    console.error("[request-audit] Resend error:", result.error);
  }

  return res.status(200).json({ ok: true });
}

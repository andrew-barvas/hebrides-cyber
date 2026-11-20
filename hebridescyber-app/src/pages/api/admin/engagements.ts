// GET /api/admin/engagements — the admin Engagements tab's list (Exploit, P-07).
//   no query                      → { customer: null, engagements } every account's, newest first
//   ?customer=<email or user id>  → { customer: { id, email }, engagements } that account's only
// Each row carries owner_email for display. The customer lookup is the same one the
// Lookout reports tab uses (lookoutCustomer.ts), so an analyst creating an
// engagement types an email, not a UUID, and gets the account id to create it under.
//
// Admin session only (requireAdmin refuses an API key). A read only: creating and
// changing an engagement stay on /api/engagements*, which hold every rule.
import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { respondInternalError } from "@/lib/apiError";
import { listAllEngagements, sendEngagementFailure } from "@/lib/engagements";
import { customerEmails, resolveLookoutCustomer } from "@/lib/lookoutCustomer";

const ROUTE = "admin/engagements";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  const input = typeof req.query.customer === "string" ? req.query.customer.trim() : "";
  let customer: { id: string; email: string | null } | null = null;
  if (input) {
    const found = await resolveLookoutCustomer(supabaseAdmin, input);
    if (!found.ok) {
      if (found.status === 500) return respondInternalError(res, ROUTE, { message: found.error }, { publicMessage: "Could not look up the account." });
      return res.status(found.status).json({ error: found.error });
    }
    customer = found.customer;
  }

  const listed = await listAllEngagements(supabaseAdmin, customer?.id ?? null);
  if (listed.status !== "ok") return sendEngagementFailure(res, ROUTE, listed);

  const emails = customer ? new Map(customer.email ? [[customer.id, customer.email]] : []) : await customerEmails(supabaseAdmin, listed.data.map((e) => e.owner));
  res.setHeader("Cache-Control", "private, no-store");
  return res.status(200).json({ customer, engagements: listed.data.map((e) => ({ ...e, owner_email: emails.get(e.owner) ?? null })) });
}

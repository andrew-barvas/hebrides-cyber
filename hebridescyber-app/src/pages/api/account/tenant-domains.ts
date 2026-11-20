// GET /api/account/tenant-domains — the connected Microsoft 365 tenant's
// verified domains, each marked as monitored or not (src/lib/tenantDomains.ts),
// so the Assets page can suggest sites the owner hasn't added. Read live with
// the existing posture consent; nothing is stored. Pro and up, like the
// connection itself.
//
// Answers 200 with { status } for every expected state (not configured, not
// connected, error with a fixed message) so the card can explain itself;
// Microsoft's own error text never reaches the browser.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { planGate } from "@/lib/planAccess";
import { respondInternalError } from "@/lib/apiError";
import { loadTenantDomains } from "@/lib/tenantDomains";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const gate = await planGate(supabaseAdmin, caller.ownerId, "pro");
  if (gate === "error") return respondInternalError(res, "account/tenant-domains", new Error("plan lookup failed"));
  if (gate === "denied") return res.status(403).json({ error: "Suggestions from Microsoft 365 are on the Pro plan and above." });

  const result = await loadTenantDomains(supabaseAdmin, caller.ownerId);
  res.setHeader("Cache-Control", "private, no-store");
  return res.status(200).json(result);
}

// POST /api/uptime/monitors { targetUrls: string[] } — create (or adopt) a
// monitor in the customer's own UptimeRobot account for each of their
// verified, monitored targets. See uptimeService.ts's createMonitorsForTargets
// for the eligibility rules; the response reports what happened per target.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { planGate } from "@/lib/planAccess";
import { checkRateLimit } from "@/lib/rateLimit";
import { createMonitorsForTargets, loadUptimeProvider, MAX_MONITORS_PER_REQUEST } from "@/lib/uptimeService";
import { parseBody } from "@/lib/validate";

const bodySchema = z.object({
  targetUrls: z.array(z.string().trim().min(1).max(2048)).min(1).max(MAX_MONITORS_PER_REQUEST * 2),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Uptime monitoring can only be managed from a logged-in session, not with an API key." });
  }

  const body = parseBody(bodySchema, req.body, res);
  if (!body) return;

  const gate = await planGate(supabaseAdmin, caller.ownerId, "pro");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan — try again." });
  if (gate === "denied") return res.status(403).json({ error: "Uptime monitoring is a Pro-and-up feature." });

  const limit = await checkRateLimit(caller.ownerId, "uptime-create", { max: 20, windowSeconds: 60 * 60 });
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many requests — try again later." });
  }

  const integration = await loadUptimeProvider(supabaseAdmin, caller.ownerId);
  if (integration.status === "error") return res.status(500).json({ error: "Could not load your uptime connection." });
  if (integration.status === "none") return res.status(400).json({ error: "Connect your UptimeRobot account first." });
  if (integration.status === "undecryptable") {
    return res.status(409).json({ error: "Your saved UptimeRobot key can no longer be read. Disconnect and connect it again." });
  }

  const results = await createMonitorsForTargets(supabaseAdmin, caller.ownerId, integration.provider, body.targetUrls);
  const created = results.filter((r) => r.result === "created" || r.result === "adopted");
  if (created.length > 0) {
    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "uptime.monitor_created",
      resourceType: "uptime_monitor",
      metadata: { provider: "uptimerobot", count: created.length, targets: created.map((r) => r.targetUrl) },
    });
  }
  return res.status(200).json({ results });
}

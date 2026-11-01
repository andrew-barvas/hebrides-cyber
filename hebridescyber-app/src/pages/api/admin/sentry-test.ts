// POST /api/admin/sentry-test: send one tagged test error to Sentry so the
// owner can prove error tracking works end to end (LAUNCH-PRIORITY.md item 2,
// AC1: "a forced error appears in Sentry within a minute"; OWNER-TODO.md OT-08).
//
// Captures rather than throws: a thrown error would also produce a 500 for the
// admin and depend on Next's own error hook firing, where captureException +
// flush gives a definite event id to search for in Sentry. Reports whether a
// DSN is configured, because without one Sentry.init() is a silent no-op and
// "sent" would otherwise be a lie.
import type { NextApiRequest, NextApiResponse } from "next";
import * as Sentry from "@sentry/nextjs";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";
import { logAuditEvent } from "@/lib/audit";

const FLUSH_TIMEOUT_MS = 5000;

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  if (!Sentry.getClient()?.getDsn()) {
    return res.status(200).json({ configured: false, eventId: null, delivered: false });
  }

  const eventId = Sentry.captureException(new Error("Sentry test error (sent from /api/admin/sentry-test)"), {
    tags: { sentry_test: "true" },
    level: "error",
  });
  const delivered = await Sentry.flush(FLUSH_TIMEOUT_MS);

  await logAuditEvent(supabaseAdmin, {
    actorId: adminId,
    action: "admin.sentry_test_sent",
    resourceType: "sentry",
    metadata: { eventId, delivered },
  });

  return res.status(200).json({ configured: true, eventId, delivered });
}

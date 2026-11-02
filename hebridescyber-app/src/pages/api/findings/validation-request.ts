// POST /api/findings/validation-request: ask for a human-run, authorised test of
// one finding in a scan report (the step from Scanner or Lookout up to Exploit).
// GET lists this account's requests so the report can show "requested".
//
//   POST { scanId, checkId, note? }
//   GET  ?scanId=<id> | neither (the whole account)
//
// This records a request and tells the operator. It sends NO traffic to the
// customer's systems: any testing happens only under a scoped, signed
// engagement (docs/EXPLOIT-PRODUCT-PLAN.md, gated by OT-13). The finding is
// snapshotted from the stored scan, never taken from the request body, so a
// request always describes something the scan really reported. Session or API
// key; a team member may act on the owner's scans, as with triage and tickets.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { sendEmail } from "@/lib/email";
import { hostOf } from "@/lib/findingLifecycle";
import { checkRateLimit } from "@/lib/rateLimit";
import type { Finding } from "@/lib/scanners";
import { callerCanActFor } from "@/lib/teamAccess";
import { NOTE_MAX, buildValidationSnapshot, operatorEmail } from "@/lib/validationRequests";
import { parseBody } from "@/lib/validate";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MIGRATION_PENDING = "Validation requests aren't enabled on this server yet (database migration 067 pending).";
const COLUMNS = "id, scan_id, target_host, check_id, severity, title, confirmed_exploitable, note, status, created_at";

// A request reaches a person, so it is limited per account.
const LIMIT = { max: 10, windowSeconds: 60 * 60 };

const postSchema = z.object({
  scanId: z.string().regex(UUID, "must be a scan id"),
  checkId: z.string().trim().min(1, "is required").max(500),
  note: z.string().trim().max(NOTE_MAX, `must be ${NOTE_MAX} characters or fewer`).optional(),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST" && req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  if (req.method === "GET") {
    const scanId = typeof req.query.scanId === "string" ? req.query.scanId : null;
    if (scanId && !UUID.test(scanId)) return res.status(400).json({ error: "scanId must be a scan id" });
    let query = supabaseAdmin.from("validation_requests").select(COLUMNS).eq("owner", caller.ownerId).order("created_at", { ascending: false }).limit(200);
    if (scanId) query = query.eq("scan_id", scanId);
    const { data, error } = await query;
    if (error) {
      if (isMissingSchemaError(error)) return res.status(200).json({ available: false, requests: [] });
      return res.status(500).json({ error: error.message });
    }
    return res.status(200).json({ available: true, requests: data ?? [] });
  }

  const parsed = parseBody(postSchema, req.body, res);
  if (!parsed) return;

  const { data: scan } = await supabaseAdmin.from("scans").select("id, owner, target_url").eq("id", parsed.scanId).maybeSingle();
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (!(await callerCanActFor(supabaseAdmin, caller.ownerId, scan.owner))) return res.status(403).json({ error: "Forbidden" });
  const host = hostOf(scan.target_url);
  if (!host) return res.status(400).json({ error: "This scan has no usable target URL" });

  const { data: result } = await supabaseAdmin.from("scan_results").select("results").eq("scan_id", parsed.scanId).order("created_at", { ascending: false }).limit(1).maybeSingle();
  const stored = ((result?.results as { findings?: Finding[] } | undefined)?.findings ?? []) as Finding[];
  const finding = stored.find((f) => f.checkId === parsed.checkId);
  if (!finding) return res.status(404).json({ error: "That finding is not in this scan" });

  const limit = await checkRateLimit(caller.ownerId, "validation-request", LIMIT);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "You have sent several requests recently. Please try again later." });
  }

  const snapshot = buildValidationSnapshot(finding);
  const note = parsed.note && parsed.note.length > 0 ? parsed.note : null;
  const { data: row, error } = await supabaseAdmin
    .from("validation_requests")
    .insert({
      owner: scan.owner,
      requested_by: caller.ownerId,
      scan_id: scan.id,
      target_host: host,
      check_id: snapshot.checkId,
      severity: snapshot.severity,
      title: snapshot.title,
      confirmed_exploitable: snapshot.confirmedExploitable,
      snapshot,
      note,
    })
    .select(COLUMNS)
    .single();
  if (error) {
    if (isMissingSchemaError(error)) return res.status(503).json({ error: MIGRATION_PENDING });
    if (error.code === "23505") return res.status(409).json({ error: "A validation request for this finding is already open." });
    return res.status(500).json({ error: error.message });
  }

  await logAuditEvent(supabaseAdmin, {
    actorId: caller.ownerId,
    action: "validation_request.created",
    resourceType: "validation_request",
    resourceId: row.id,
    metadata: { host, check_id: snapshot.checkId, severity: snapshot.severity },
  });

  const { data: user } = await supabaseAdmin.from("users").select("email").eq("id", caller.ownerId).maybeSingle();
  const mail = operatorEmail({ requesterEmail: (user as { email?: string | null } | null)?.email ?? null, host, snapshot, note, requestId: row.id });
  const sent = await sendEmail({ to: process.env.CONTACT_EMAIL ?? "hello@hebridescyber.co.uk", ...mail });
  // The request is saved either way; an unsent email is logged, not surfaced as a failure.
  if (!sent.ok && sent.error !== "RESEND_API_KEY not configured") console.error("[validation-request] email failed:", sent.error);

  return res.status(201).json({
    request: row,
    message: "Request received. Nothing has been tested. We will contact you to agree the scope and get your written authorisation first.",
  });
}

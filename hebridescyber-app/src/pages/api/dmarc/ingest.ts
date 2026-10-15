// POST /api/dmarc/ingest — receives a DMARC aggregate (RUA) report (E-66).
//
// A customer points their DMARC record's rua= at a mailbox/forwarding provider
// that POSTs each report here. Auth is a per-owner ingest token (query ?token=
// or Authorization: Bearer) resolved to the owning account — there's no user
// session on this path, the sender is a mail robot. The body is the raw report:
// gzip'd XML (the common case), zip, or plain XML. We gunzip, parse with
// dmarcAggregate.ts, and upsert one dmarc_reports row (idempotent on
// owner+domain+report_id). Rate-limited per IP like the other public writes.
import type { NextApiRequest, NextApiResponse } from "next";
import { buffer } from "node:stream/consumers";
import { gunzipSync } from "node:zlib";
import { supabaseAdmin } from "@/lib/supabaseAdmin";
import { checkRateLimit, getClientIp, type RateLimitPolicy } from "@/lib/rateLimit";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { parseDmarcAggregateReport } from "@/lib/dmarcAggregate";
import { toReportInsert, resolveIngestToken } from "@/lib/dmarcReports";

export const config = { api: { bodyParser: false } };

const MAX_BODY_BYTES = 10 * 1024 * 1024; // 10 MB — aggregate reports are small
// A busy domain can receive many reports a day from many reporters; 60/hr/IP is
// generous for legitimate senders and still caps abuse.
const INGEST_RATE_LIMIT: RateLimitPolicy = { max: 60, windowSeconds: 3600 };

function decode(raw: Buffer): string | null {
  // gzip magic 1f 8b; otherwise assume plain XML. (zip is rarer and needs a
  // central-directory parse — if we ever see one in practice, add it; for now a
  // non-gzip, non-XML body simply fails to parse and is rejected below.)
  try {
    if (raw.length >= 2 && raw[0] === 0x1f && raw[1] === 0x8b) {
      return gunzipSync(raw).toString("utf8");
    }
    return raw.toString("utf8");
  } catch {
    return null;
  }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const rl = await checkRateLimit(getClientIp(req), "dmarc-ingest", INGEST_RATE_LIMIT);
  if (!rl.allowed) return res.status(429).json({ error: "Rate limit exceeded" });

  const bearer = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  const token = (typeof req.query.token === "string" ? req.query.token : undefined) ?? bearer;
  const owner = await resolveIngestToken(supabaseAdmin, token);
  if (!owner) return res.status(401).json({ error: "Invalid or missing ingest token" });

  let raw: Buffer;
  try {
    raw = await buffer(req);
  } catch {
    return res.status(400).json({ error: "Could not read request body" });
  }
  if (raw.length > MAX_BODY_BYTES) {
    return res.status(413).json({ error: "Report too large" });
  }

  const xml = decode(raw);
  if (!xml) return res.status(400).json({ error: "Could not decompress report body" });

  const report = parseDmarcAggregateReport(xml);
  if (!report) return res.status(400).json({ error: "Not a parseable DMARC aggregate report" });

  // Fall back to the token owner's... we don't know their domain here, so the
  // report's own policy_published domain is authoritative; if it's absent we
  // use "unknown" rather than guess, so the row is still stored and visible.
  const insert = toReportInsert(owner, report, "unknown");

  const { error } = await supabaseAdmin
    .from("dmarc_reports")
    .upsert(insert, { onConflict: "owner,domain,report_id" });

  if (error) {
    if (isMissingSchemaError(error)) {
      return res.status(503).json({ error: "DMARC report storage isn't available yet (migration 060 pending)" });
    }
    return res.status(500).json({ error: error.message });
  }

  return res.status(202).json({
    accepted: true,
    domain: insert.domain,
    org: insert.org_name,
    total: insert.total_messages,
    passing: insert.passing_messages,
    failing: insert.failing_messages,
  });
}

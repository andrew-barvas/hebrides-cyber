// Public REST API — POST /api/v1/scans (run a scan), GET /api/v1/scans (list).
//
// Was fully synchronous — one call ran the whole check suite inline and
// returned the finished report. That shared the same failure mode the
// dashboard's "Run scan" button hit in production: Azure Static Web Apps'
// Free-tier managed Functions have an execution ceiling this route could
// exceed on a slow-to-check site, killing the request with a proxy error
// before any JSON was ever returned (`az staticwebapp functions show`
// refuses to even run on Free SKU, which is the strongest signal available
// that this ceiling is real and not app-configurable).
//
// Now queues via the same scan_jobs path run-scan.ts uses (see that file and
// .github/workflows/on-demand-scan.yml) and returns 202 immediately. This is
// a breaking change for existing integrations that expected the full report
// in one call — docs/API.md and action/index.js are updated accordingly, and
// callers now poll GET /api/v1/scans/{id} (already returns a pending shape
// with `status`, see pendingScanReport in scanReport.ts — needed no changes)
// or use webhooks, which were already the documented "don't poll" option.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { validateNoSsrf, hostnameFromUrl, isDomainVerified } from "@/lib/ownership";
import { checkRateLimit } from "@/lib/rateLimit";
import { supabaseAdmin } from "@/lib/apiAuth";
import { guardV1, setV1Headers } from "@/lib/v1Guard";
import { isFreeTierExhausted, FREE_TIER_EXHAUSTED_MESSAGE } from "@/lib/freeTier";
import { triggerOnDemandWorkflow } from "@/lib/onDemandScanTrigger";
import { parseBody } from "@/lib/validate";
import { clientParam, resolveClientScope } from "@/lib/clientScope";

const createScanSchema = z.object({
  target_url: z.string().url("target_url must be a valid URL"),
});

export const config = { api: { bodyParser: { sizeLimit: "1mb" } } };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    const caller = await guardV1(req, res, "scans:read");
    if (!caller) return;
    return listScans(req, res, caller.ownerId);
  }
  if (req.method === "POST") {
    // Queueing a scan has its own, stricter per-account budget below (shared with run-scan).
    const caller = await guardV1(req, res, "scans:write", { rateLimit: false });
    if (!caller) return;
    return createScan(req, res, caller.ownerId);
  }
  setV1Headers(res);
  res.setHeader("Allow", "GET, POST");
  return res.status(405).json({ error: "Method not allowed", code: "method_not_allowed" });
}

async function listScans(req: NextApiRequest, res: NextApiResponse, ownerId: string) {
  const limit = Math.min(Number(req.query.limit) || 20, 100);
  const targetUrl = typeof req.query.target_url === "string" ? req.query.target_url : null;

  let query = supabaseAdmin
    .from("scans")
    .select("id, target_url, status, created_at, scan_results(score, summary)")
    .eq("owner", ownerId)
    .order("created_at", { ascending: false })
    .limit(limit);

  if (targetUrl) query = query.eq("target_url", targetUrl);

  // ?client=<id>|unassigned narrows to that client's sites. Scans are matched
  // to sites by hostname, so filter after the query and over-fetch to keep `limit` useful.
  const client = clientParam(req.query.client);
  let hosts: Set<string> | null = null;
  if (client) {
    const scope = await resolveClientScope(supabaseAdmin, ownerId, client);
    if (!scope.ok) return res.status(scope.status).json({ error: scope.error, code: scope.status === 404 ? "client_not_found" : "client_unavailable" });
    hosts = scope.hosts;
    query = query.limit(500);
  }

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });

  const matching = hosts
    ? (data ?? []).filter((s: Record<string, unknown>) => {
        try {
          return hosts.has(hostnameFromUrl(String(s.target_url)).toLowerCase());
        } catch {
          return false;
        }
      }).slice(0, limit)
    : (data ?? []);

  const scans = matching.map((s: Record<string, unknown>) => {
    const nested = s.scan_results as { score?: number | null; summary?: string | null }[] | null;
    return {
      scan_id: s.id,
      target_url: s.target_url,
      status: s.status,
      created_at: s.created_at,
      score: nested?.[0]?.score ?? null,
      summary: nested?.[0]?.summary ?? null,
    };
  });

  return res.status(200).json({ scans, count: scans.length });
}

async function createScan(req: NextApiRequest, res: NextApiResponse, ownerId: string) {
  const parsed = parseBody(createScanSchema, req.body, res);
  if (!parsed) return;
  const targetUrl = parsed.target_url;

  const limit = await checkRateLimit(ownerId);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds ?? 60));
    return res.status(429).json({ error: "Rate limit exceeded", code: "rate_limited", retry_after_seconds: limit.retryAfterSeconds });
  }

  if (await isFreeTierExhausted(supabaseAdmin, ownerId)) {
    return res.status(402).json({ error: FREE_TIER_EXHAUSTED_MESSAGE, code: "free_tier_exhausted" });
  }

  try {
    await validateNoSsrf(targetUrl);
  } catch (err) {
    return res.status(400).json({ error: `Invalid target: ${(err as Error).message}` });
  }

  // Ownership must already be verified — see the file header for why the
  // interactive proof-token path isn't available to API callers. (Admins
  // bypass this — see isDomainVerified.)
  let domain: string;
  try {
    domain = hostnameFromUrl(targetUrl);
  } catch {
    return res.status(400).json({ error: "Could not parse hostname from target_url" });
  }

  if (!(await isDomainVerified(supabaseAdmin, ownerId, targetUrl))) {
    return res.status(403).json({
      error: `Domain "${domain}" is not verified for this account. Verify it in the dashboard before scanning it via the API.`,
      domain,
    });
  }

  // Dedupe: return an in-flight scan for the same target rather than stacking
  // a duplicate — a CI job that retries POST /api/v1/scans, or a loop, should
  // not create a pile of identical scans. Matches run-scan.ts's guard.
  const inflightSince = new Date(Date.now() - 30 * 60 * 1000).toISOString();
  const { data: inflight } = await supabaseAdmin
    .from("scans")
    .select("id, status")
    .eq("owner", ownerId)
    .eq("target_url", targetUrl)
    .in("status", ["queued", "running"])
    .gt("created_at", inflightSince)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (inflight) {
    return res.status(202).json({
      scan_id: inflight.id,
      target_url: targetUrl,
      status: inflight.status,
      deduped: true,
      message: "A scan for this URL is already in progress — returning it. Poll GET /api/v1/scans/{id} or register a webhook for scan.completed.",
    });
  }

  const { data: scan, error: createErr } = await supabaseAdmin
    .from("scans")
    .insert({ owner: ownerId, target_url: targetUrl, status: "queued", owner_verified: true })
    .select("id")
    .single();

  if (createErr || !scan) {
    return res.status(500).json({ error: createErr?.message ?? "Failed to create scan" });
  }

  // Enqueue rather than call executeScan() directly — see this file's header
  // comment. scan_id is pre-set so run-queued-scan-jobs.ts reuses this row
  // and stays passive-only (same as every other on-demand path), rather than
  // creating a second scans row and running the active-scanning tool suite
  // the way scheduled jobs do.
  const { error: jobError } = await supabaseAdmin.from("scan_jobs").insert({
    owner: ownerId,
    target_url: targetUrl,
    scan_id: scan.id,
    status: "pending",
  });
  if (jobError) {
    await supabaseAdmin.from("scans").update({ status: "failed" }).eq("id", scan.id);
    return res.status(500).json({ error: `Failed to queue scan: ${jobError.message}` });
  }

  // Awaited so the dispatch call isn't cut off by the function returning —
  // never throws or blocks beyond its own 6s timeout, see
  // triggerOnDemandWorkflow's doc comment.
  await triggerOnDemandWorkflow();

  return res.status(202).json({
    scan_id: scan.id,
    target_url: targetUrl,
    status: "queued",
    message: "Scan queued — usually completes within a minute. Poll GET /api/v1/scans/{id} or register a webhook for scan.completed.",
  });
}

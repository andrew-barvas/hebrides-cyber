// Public REST API — POST /api/v1/scans (run a scan), GET /api/v1/scans (list).
//
// Unlike the dashboard's two-step /api/run-scan (create → prove ownership →
// run), this runs the whole flow in one call. That's only safe because it
// requires the domain to already be verified: an API key must not be able to
// point the scanner at a host its owner hasn't proven they control, and
// there's no interactive step in CI to complete a challenge.
import type { NextApiRequest, NextApiResponse } from "next";
import { validateNoSsrf, hostnameFromUrl, isDomainVerified } from "@/lib/ownership";
import { checkRateLimit } from "@/lib/rateLimit";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { executeScan } from "@/lib/scanExecution";
import { isFreeTierExhausted, FREE_TIER_EXHAUSTED_MESSAGE } from "@/lib/freeTier";

export const config = { api: { bodyParser: { sizeLimit: "1mb" } } };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) {
    return res.status(401).json({ error: "Missing or invalid Authorization header. Use: Authorization: Bearer <api-key>" });
  }

  if (req.method === "GET") return listScans(req, res, caller.ownerId);
  if (req.method === "POST") return createScan(req, res, caller.ownerId);
  return res.status(405).json({ error: "Method not allowed" });
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

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });

  const scans = (data ?? []).map((s: Record<string, unknown>) => {
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
  const { target_url: targetUrl } = req.body as { target_url?: string };
  if (!targetUrl) return res.status(400).json({ error: "target_url is required" });

  const limit = await checkRateLimit(ownerId);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds ?? 60));
    return res.status(429).json({ error: "Rate limit exceeded", retry_after_seconds: limit.retryAfterSeconds });
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

  const { data: scan, error: createErr } = await supabaseAdmin
    .from("scans")
    .insert({ owner: ownerId, target_url: targetUrl, status: "running", owner_verified: true })
    .select("id")
    .single();

  if (createErr || !scan) {
    return res.status(500).json({ error: createErr?.message ?? "Failed to create scan" });
  }

  // Same executeScan() the dashboard's run-scan Function and the scheduled
  // queue's workers use — one implementation of "run the checks, persist,
  // notify" rather than a third copy that can drift (this used to duplicate
  // it inline, including never sending the Slack change-alert other paths
  // get). Awaited, not fire-and-forget: a serverless function can be torn
  // down the moment the response is sent, which would silently kill an
  // un-awaited webhook delivery mid-flight.
  const outcome = await executeScan(supabaseAdmin, scan.id, ownerId, targetUrl);
  if (!outcome.ok) {
    return res.status(500).json({ error: `Scan failed: ${outcome.error}`, scan_id: scan.id });
  }

  return res.status(201).json(outcome.report);
}

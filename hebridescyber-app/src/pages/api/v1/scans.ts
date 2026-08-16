// Public REST API — POST /api/v1/scans (run a scan), GET /api/v1/scans (list).
//
// Unlike the dashboard's two-step /api/run-scan (create → prove ownership →
// run), this runs the whole flow in one call. That's only safe because it
// requires the domain to already be verified: an API key must not be able to
// point the scanner at a host its owner hasn't proven they control, and
// there's no interactive step in CI to complete a challenge.
import type { NextApiRequest, NextApiResponse } from "next";
import { runAllChecks, summariseResults, scoreFromFindings, generateAiSummary } from "@/lib/scanners";
import { validateNoSsrf, hostnameFromUrl } from "@/lib/ownership";
import { checkRateLimit } from "@/lib/rateLimit";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";

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

  try {
    await validateNoSsrf(targetUrl);
  } catch (err) {
    return res.status(400).json({ error: `Invalid target: ${(err as Error).message}` });
  }

  // Ownership must already be verified — see the file header for why the
  // interactive proof-token path isn't available to API callers.
  let domain: string;
  try {
    domain = hostnameFromUrl(targetUrl);
  } catch {
    return res.status(400).json({ error: "Could not parse hostname from target_url" });
  }

  const { data: verification } = await supabaseAdmin
    .from("verifications")
    .select("verified_at")
    .eq("owner", ownerId)
    .eq("domain", domain)
    .maybeSingle();

  if (!verification?.verified_at) {
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

  try {
    const results = await runAllChecks(targetUrl);
    const { findings } = summariseResults(results);
    const score = scoreFromFindings(findings);
    const summary = await generateAiSummary(results, findings);

    const { error: insertErr } = await supabaseAdmin
      .from("scan_results")
      .insert({ scan_id: scan.id, results: { ...results, findings }, summary, score });

    if (insertErr) throw new Error(insertErr.message);

    await supabaseAdmin.from("scans").update({ status: "completed" }).eq("id", scan.id);

    const counts = findings.reduce<Record<string, number>>((acc, f) => {
      acc[f.severity] = (acc[f.severity] ?? 0) + 1;
      return acc;
    }, {});

    return res.status(201).json({
      scan_id: scan.id,
      target_url: targetUrl,
      status: "completed",
      score,
      summary,
      counts,
      findings: findings.map((f) => ({
        check_id: f.checkId ?? null,
        severity: f.severity,
        title: f.title,
        detail: f.detail,
        remediation: f.remediation ?? null,
      })),
    });
  } catch (err) {
    await supabaseAdmin.from("scans").update({ status: "failed" }).eq("id", scan.id);
    return res.status(500).json({ error: `Scan failed: ${(err as Error).message}`, scan_id: scan.id });
  }
}

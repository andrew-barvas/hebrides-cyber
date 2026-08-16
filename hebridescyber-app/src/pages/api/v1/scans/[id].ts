// GET /api/v1/scans/{id} — full scan result, with each finding tagged
// new/unchanged relative to the previous scan of the same target.
//
// That per-finding status is the point of this endpoint for CI: it lets a
// pipeline fail only on newly introduced issues instead of the whole existing
// backlog. Gating on total findings would red-line every pipeline on its first
// run, and the check would be disabled the same day.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { diffFindings } from "@/lib/findingsDiff";
import type { Finding } from "@/lib/scanners";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const scanId = req.query.id as string;

  const { data: scan } = await supabaseAdmin
    .from("scans")
    .select("id, owner, target_url, status, created_at")
    .eq("id", scanId)
    .maybeSingle();

  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (scan.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  const { data: result } = await supabaseAdmin
    .from("scan_results")
    .select("results, summary, score, created_at")
    .eq("scan_id", scanId)
    .maybeSingle();

  if (!result) {
    return res.status(200).json({
      scan_id: scan.id,
      target_url: scan.target_url,
      status: scan.status,
      created_at: scan.created_at,
      score: null,
      findings: [],
    });
  }

  const findings: Finding[] = (result.results?.findings as Finding[] | undefined) ?? [];
  const previous = await findPreviousFindings(scan.owner, scan.id, scan.target_url, scan.created_at);
  const diff = previous ? diffFindings(findings, previous) : null;

  const statusByCheckId = new Map<string, "new" | "unchanged">();
  if (diff) {
    diff.added.forEach((f) => f.checkId && statusByCheckId.set(f.checkId, "new"));
    diff.unchanged.forEach((f) => f.checkId && statusByCheckId.set(f.checkId, "unchanged"));
  }

  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  return res.status(200).json({
    scan_id: scan.id,
    target_url: scan.target_url,
    status: scan.status,
    created_at: scan.created_at,
    completed_at: result.created_at,
    score: result.score,
    summary: result.summary,
    counts,
    // null when this is the first scan of the target — callers should treat a
    // null comparison as "cannot tell what's new", not as "nothing is new".
    compared_to_previous_scan: Boolean(diff),
    new_finding_count: diff ? diff.added.length : null,
    fixed_finding_count: diff ? diff.fixed.length : null,
    findings: findings.map((f) => ({
      check_id: f.checkId ?? null,
      severity: f.severity,
      title: f.title,
      detail: f.detail,
      remediation: f.remediation ?? null,
      status: f.checkId ? statusByCheckId.get(f.checkId) ?? null : null,
    })),
    fixed_findings: diff
      ? diff.fixed.map((f) => ({ check_id: f.checkId ?? null, severity: f.severity, title: f.title }))
      : [],
  });
}

/**
 * Most recent completed scan of the same host, older than this one.
 * Matches on hostname rather than exact target_url — target_url is stored raw,
 * so protocol/trailing-slash/case differences would otherwise hide a match.
 */
async function findPreviousFindings(
  ownerId: string,
  currentScanId: string,
  targetUrl: string,
  createdAt: string
): Promise<Finding[] | null> {
  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    return null;
  }

  const { data: candidates } = await supabaseAdmin
    .from("scans")
    .select("id, target_url, scan_results(results)")
    .eq("owner", ownerId)
    .eq("status", "completed")
    .neq("id", currentScanId)
    .lt("created_at", createdAt)
    .order("created_at", { ascending: false })
    .limit(100);

  for (const c of (candidates ?? []) as Array<{
    target_url: string;
    scan_results: { results: { findings?: Finding[] } }[];
  }>) {
    let host: string;
    try {
      host = new URL(c.target_url).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (host !== hostname) continue;
    const prev = c.scan_results?.[0]?.results?.findings;
    if (prev) return prev;
  }

  return null;
}

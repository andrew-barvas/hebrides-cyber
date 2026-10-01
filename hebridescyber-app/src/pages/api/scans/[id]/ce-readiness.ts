import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { assessCeReadiness } from "@/lib/cyberEssentialsReadiness";
import type { Finding } from "@/lib/scanners";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });

  const scanId = req.query.id as string;
  if (!scanId) return res.status(400).json({ error: "Missing scan ID" });

  const { data: scan } = await supabaseAdmin
    .from("scans")
    .select("id, owner, status")
    .eq("id", scanId)
    .maybeSingle();

  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (scan.owner !== caller.ownerId) return res.status(403).json({ error: "Not your scan" });
  if (scan.status !== "completed") return res.status(400).json({ error: "Scan not yet completed" });

  const { data: result } = await supabaseAdmin
    .from("scan_results")
    .select("results")
    .eq("scan_id", scanId)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!result?.results) return res.status(404).json({ error: "No scan results found" });

  const findings: Finding[] = (result.results as Record<string, unknown>).findings as Finding[] ?? [];
  const report = assessCeReadiness(findings);

  return res.status(200).json(report);
}

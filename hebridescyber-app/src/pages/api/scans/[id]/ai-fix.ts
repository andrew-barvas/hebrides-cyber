// On-demand AI-tailored remediation for a single finding — POST { checkId }.
// Session or API key (read-mostly, no account-level side effects, so it
// follows /api/v1/scans' dual-auth rather than keys.ts/shares.ts's
// session-only restriction).
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { generateAiRemediation } from "@/lib/aiRemediation";
import { checkRateLimit } from "@/lib/rateLimit";
import type { Finding, ScanResults } from "@/lib/scanners";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  // E-12 (docs/ENHANCEMENTS.md): uncapped Azure OpenAI token spend per call,
  // one of only 2 of ~30 routes with any rate limit before this.
  const limit = await checkRateLimit(caller.ownerId, "ai-fix");
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Rate limit exceeded — try again later", retryAfterSeconds: limit.retryAfterSeconds });
  }

  const scanId = req.query.id as string;
  const { checkId } = req.body as { checkId?: string };
  if (!checkId) return res.status(400).json({ error: "checkId is required" });

  const { data: scan } = await supabaseAdmin.from("scans").select("id, owner").eq("id", scanId).maybeSingle();
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (scan.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  const { data: result } = await supabaseAdmin
    .from("scan_results")
    .select("results")
    .eq("scan_id", scanId)
    .maybeSingle();
  if (!result) return res.status(404).json({ error: "No results for this scan yet" });

  const stored = result.results as ScanResults & { findings?: Finding[] };
  const finding = (stored.findings ?? []).find((f) => f.checkId === checkId);
  if (!finding) return res.status(404).json({ error: `No finding with checkId "${checkId}" on this scan` });

  const technologies = stored.fingerprint?.status === "checked" ? stored.fingerprint.technologies : [];

  const outcome = await generateAiRemediation(finding, technologies);

  if (outcome.status === "not_configured") {
    return res.status(501).json({ error: "AI-tailored remediation is not configured on this deployment." });
  }
  if (outcome.status === "error") {
    return res.status(502).json({ error: `AI remediation request failed: ${outcome.message}` });
  }
  return res.status(200).json({ guidance: outcome.guidance });
}

// POST /api/scans/{id}/create-ticket — turns one finding into a real Jira or
// Linear issue, using whichever provider the caller has configured (see
// src/pages/api/account/ticket-integration.ts). Same shape as
// ai-fix.ts: session or API key, scan ownership required, checkId identifies
// the finding within the scan's already-stored results.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { createJiraIssue, createLinearIssue } from "@/lib/ticketIntegrations";
import type { Finding, ScanResults } from "@/lib/scanners";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  const scanId = req.query.id as string;
  const { checkId } = req.body as { checkId?: string };
  if (!checkId) return res.status(400).json({ error: "checkId is required" });

  const { data: scan } = await supabaseAdmin.from("scans").select("id, owner, target_url").eq("id", scanId).maybeSingle();
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  if (scan.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

  const { data: result } = await supabaseAdmin.from("scan_results").select("results").eq("scan_id", scanId).maybeSingle();
  if (!result) return res.status(404).json({ error: "No results for this scan yet" });

  const stored = result.results as ScanResults & { findings?: Finding[] };
  const finding = (stored.findings ?? []).find((f) => f.checkId === checkId);
  if (!finding) return res.status(404).json({ error: `No finding with checkId "${checkId}" on this scan` });

  const { data: integration } = await supabaseAdmin
    .from("ticket_integrations")
    .select("provider, jira_base_url, jira_email, jira_api_token, jira_project_key, linear_api_key, linear_team_id")
    .eq("owner", caller.ownerId)
    .maybeSingle();

  if (!integration) {
    return res.status(501).json({ error: "No ticket integration configured — connect Jira or Linear in Account settings first." });
  }

  const reportUrl = `${process.env.NEXT_PUBLIC_SITE_URL ?? "https://hebridescyber.com"}/dashboard/scans/${scanId}`;
  const ticket = {
    title: `[${finding.severity.toUpperCase()}] ${finding.title}`,
    body: `${finding.detail}\n\n${finding.remediation ?? ""}`.trim(),
    reportUrl,
  };

  const outcome =
    integration.provider === "jira"
      ? await createJiraIssue(
          {
            baseUrl: integration.jira_base_url,
            email: integration.jira_email,
            apiToken: integration.jira_api_token,
            projectKey: integration.jira_project_key,
          },
          ticket
        )
      : await createLinearIssue({ apiKey: integration.linear_api_key, teamId: integration.linear_team_id }, ticket);

  if (!outcome.ok) return res.status(502).json({ error: outcome.error });
  return res.status(200).json({ ok: true, provider: integration.provider, url: outcome.url });
}

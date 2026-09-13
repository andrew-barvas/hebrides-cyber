// POST /api/scans/{id}/create-ticket — turns one finding into a real Jira or
// Linear issue, using whichever provider the caller has configured (see
// src/pages/api/account/ticket-integration.ts). Same shape as
// ai-fix.ts: session or API key, scan ownership required, checkId identifies
// the finding within the scan's already-stored results.
//
// Idempotent since sql/migrations/016_ticket_links.sql: a finding that
// already has a live issue gets a "re-detected" comment on that issue and
// its existing URL back, instead of a second identical ticket. See
// decideTicketAction() in src/lib/ticketLinks.ts for the full decision table
// — including why a tracker we can't reach means doing nothing at all rather
// than guessing.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { checkRateLimit } from "@/lib/rateLimit";
import {
  buildProviderClient,
  decideTicketAction,
  findTicketLink,
  recordTicketLink,
  ticketHostOf,
  touchTicketLink,
  type TicketIntegrationRow,
} from "@/lib/ticketLinks";
import { callerCanActFor } from "@/lib/teamAccess";
import type { Finding, ScanResults } from "@/lib/scanners";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  // E-12 (docs/ENHANCEMENTS.md): real Jira/Linear API calls per request,
  // uncapped before this.
  const limit = await checkRateLimit(caller.ownerId, "create-ticket");
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Rate limit exceeded — try again later", retryAfterSeconds: limit.retryAfterSeconds });
  }

  const scanId = req.query.id as string;
  const { checkId } = req.body as { checkId?: string };
  if (!checkId) return res.status(400).json({ error: "checkId is required" });

  const { data: scan } = await supabaseAdmin.from("scans").select("id, owner, target_url").eq("id", scanId).maybeSingle();
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  const isOwner = scan.owner === caller.ownerId;
  if (!isOwner && !(await callerCanActFor(supabaseAdmin, caller.ownerId, scan.owner))) {
    return res.status(403).json({ error: "Forbidden" });
  }
  // Q4 #18: a team 'admin'/'developer' can create a ticket on the owner's
  // behalf — using the OWNER's own ticket integration (their Jira/Linear),
  // never the caller's, and recorded against the owner in ticket_links.
  const actingOwnerId = scan.owner;

  const { data: result } = await supabaseAdmin.from("scan_results").select("results").eq("scan_id", scanId).maybeSingle();
  if (!result) return res.status(404).json({ error: "No results for this scan yet" });

  const stored = result.results as ScanResults & { findings?: Finding[] };
  const finding = (stored.findings ?? []).find((f) => f.checkId === checkId);
  if (!finding) return res.status(404).json({ error: `No finding with checkId "${checkId}" on this scan` });

  // ticket_integrations is unique on (owner, provider), so an owner who has
  // connected BOTH Jira and Linear has two rows — a bare .maybeSingle() here
  // used to throw on exactly that account. Take the most recently connected
  // one deterministically instead.
  const { data: integration } = await supabaseAdmin
    .from("ticket_integrations")
    .select("provider, jira_base_url, jira_email, jira_api_token, jira_project_key, linear_api_key, linear_team_id, auto_close_enabled")
    .eq("owner", actingOwnerId)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!integration) {
    return res.status(501).json({ error: "No ticket integration configured — connect Jira or Linear in Account settings first." });
  }

  const client = buildProviderClient(integration as TicketIntegrationRow);
  if (!client) {
    return res.status(501).json({ error: `The saved ${integration.provider} integration is missing required credentials — reconnect it in Account settings.` });
  }

  const targetHost = ticketHostOf(scan.target_url);
  const link = await findTicketLink(supabaseAdmin, actingOwnerId, client.provider, targetHost, checkId);
  // Only worth asking the tracker about a link we might reuse; a row already
  // marked closed is a regression and takes the create path regardless.
  const issueState = link && !link.closed_at ? await client.getIssue(link.issue_key) : null;
  const decision = decideTicketAction(link, issueState);

  if (decision.action === "blocked") {
    return res.status(502).json({ error: `Could not confirm the existing ticket's state: ${decision.error}` });
  }

  if (decision.action === "existing") {
    const note = decision.alreadyResolved
      ? `This issue is marked resolved, but Hebrides Cyber still detected the finding on ${scan.target_url} at ${new Date().toISOString()}.`
      : `Vulnerability re-detected on ${scan.target_url} at ${new Date().toISOString()}.`;
    const commented = await client.addComment(decision.issueKey, note);
    if (link) await touchTicketLink(supabaseAdmin, link.id);
    return res.status(200).json({
      ok: true,
      provider: client.provider,
      url: decision.issueUrl,
      deduplicated: true,
      alreadyResolved: decision.alreadyResolved,
      // Surfaced rather than swallowed: the ticket genuinely wasn't updated
      // if this failed, and the caller shouldn't be told it was.
      commentAdded: commented.ok,
      ...(commented.ok ? {} : { commentError: commented.error }),
    });
  }

  const reportUrl = `${process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk"}/dashboard/scans/${scanId}`;
  const outcome = await client.createIssue({
    title: `[${finding.severity.toUpperCase()}] ${finding.title}`,
    body: `${finding.detail}\n\n${finding.remediation ?? ""}`.trim(),
    reportUrl,
  });

  if (!outcome.ok) return res.status(502).json({ error: outcome.error });

  await recordTicketLink(supabaseAdmin, {
    owner: actingOwnerId,
    provider: client.provider,
    targetHost,
    checkId,
    issueKey: outcome.issueKey,
    issueUrl: outcome.url,
  });

  return res.status(200).json({ ok: true, provider: client.provider, url: outcome.url, deduplicated: false, reason: decision.reason });
}

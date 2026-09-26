// Closes the Jira/Linear issues for findings a later scan confirmed gone.
//
// The retest half of the ticket lifecycle: create-ticket.ts opens an issue
// and records it in ticket_links, and this closes that issue once the
// finding stops appearing. The "did it stop appearing" judgement is not made
// here — ScanReport.fixed_findings already carries it, computed by
// findingsDiff.ts against the previous scan of the same host, keyed on the
// same check_id the ledger uses. So this is a ledger lookup and two API
// calls, not a second opinion about what counts as fixed.
//
// OPT-IN, and off unless ticket_integrations.auto_close_enabled is true
// (see sql/migrations/016_ticket_links.sql). Transitioning an issue in
// someone else's tracker is a visible action in a system this app doesn't
// own, and an account that connected Jira before this existed must not find
// its board moving on its own.
//
// Never throws — same contract as sendCriticalAlertEmail/sendChangeAlertIfDue,
// since this runs inside executeScan's post-completion phase where a failure
// must not affect a scan that has already succeeded and been recorded.
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  buildProviderClient,
  findOpenTicketLinks,
  findTicketIntegration,
  markTicketLinkClosed,
  ticketHostOf,
} from "./ticketLinks";
import type { ScanReport } from "./scanReport";

export type AutoCloseSummary = {
  closed: number;
  failed: number;
  /** Open tickets whose finding is still present — left alone, counted for logging. */
  stillOpen: number;
};

const NOOP: AutoCloseSummary = { closed: 0, failed: 0, stillOpen: 0 };

export async function autoCloseFixedFindingTickets(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  report: ScanReport
): Promise<AutoCloseSummary> {
  try {
    // No previous scan to compare against means nothing can be *known* to be
    // fixed — a first-ever scan finding nothing is not evidence that anything
    // was resolved.
    const fixedCheckIds = new Set(
      (report.fixed_findings ?? []).map((f) => f.check_id).filter((id): id is string => Boolean(id))
    );
    if (fixedCheckIds.size === 0) return NOOP;

    // Trackers only — before findTicketIntegration filtered by provider,
    // connecting PagerDuty or Opsgenie (same table, 028) after Jira made this
    // pick the on-call row and silently stop auto-closing.
    const integration = await findTicketIntegration(supabaseAdmin, ownerId);

    if (!integration?.auto_close_enabled) return NOOP;

    const client = buildProviderClient(integration);
    if (!client) {
      console.error(`[ticketAutoClose] ${integration.provider} integration for owner ${ownerId} is missing credentials — skipping`);
      return NOOP;
    }

    const targetHost = ticketHostOf(report.target_url);
    const openLinks = await findOpenTicketLinks(supabaseAdmin, ownerId, client.provider, targetHost);
    if (openLinks.length === 0) return NOOP;

    const summary: AutoCloseSummary = { closed: 0, failed: 0, stillOpen: 0 };

    for (const link of openLinks) {
      if (!fixedCheckIds.has(link.check_id)) {
        summary.stillOpen++;
        continue;
      }

      // Close first, comment only on success. A workflow that can't reach a
      // done status from the issue's current one would otherwise collect an
      // identical "verified as fixed" comment on every nightly scan forever,
      // since nothing records that we already said it — the ledger row stays
      // open precisely because the close didn't happen.
      const closed = await client.closeIssue(link.issue_key);
      if (!closed.ok) {
        summary.failed++;
        console.error(`[ticketAutoClose] could not close ${link.issue_key} for ${link.check_id}: ${closed.error}`);
        continue;
      }

      await client.addComment(
        link.issue_key,
        `Automatically verified as fixed on ${new Date().toISOString()} — this finding was no longer detected on ${report.target_url} by Hebrides Cyber.`
      );
      await markTicketLinkClosed(supabaseAdmin, link.id);
      summary.closed++;
    }

    return summary;
  } catch (err) {
    console.error(`[ticketAutoClose] threw for scan ${report.scan_id}:`, (err as Error).message);
    return NOOP;
  }
}

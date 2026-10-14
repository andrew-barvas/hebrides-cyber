// E-54: PagerDuty / Opsgenie on-call alerting — fires when a completed scan
// surfaces a new Critical severity finding, and resolves the corresponding
// incident/alert once a later scan confirms the finding is gone.
//
// Reuses ticket_integrations (provider 'pagerduty'/'opsgenie', see
// sql/migrations/028_oncall_integrations.sql +
// sql/migrations/039_oncall_credential_columns.sql) rather than a new table —
// same one-row-per-owner+provider shape as jira/linear. Unlike jira/linear,
// there is no auto_close_enabled gate here: for these two providers a row
// existing IS the "active" signal, matching the Slack/Teams webhook
// precedent (slack_webhook_url — set = active, see CLAUDE.md). auto_close_
// enabled stays scoped to ticketAutoClose.ts's jira/linear ticket-closing
// feature and is never read by this module.
//
// No ledger table, unlike ticket_links.ts. PagerDuty's dedup_key and
// Opsgenie's alias are both caller-supplied idempotent identifiers, so a
// deterministic key computed from (owner, target host, check id) lets a
// repeat trigger update the same incident instead of duplicating it, and lets
// resolve() recompute the identical key without ever having stored one.
// Resolving a dedup_key/alias that was never triggered (e.g. we never had a
// pagerduty integration configured when the finding first appeared) is a
// harmless no-op in both APIs — resolvePagerDutyIncident/resolveOpsgenieAlert
// already swallow the response and just return a boolean either way.
//
// Trigger condition is deliberately narrower than sendCriticalAlertEmail's:
// only NEW findings at severity "critical" (not "high") — matches E-54's
// literal spec ("new Critical severity finding"). On-call paging is for the
// smaller, louder set; email already covers critical+high.
//
// Never throws — same contract as scanAlerts.ts/ticketAutoClose.ts, since
// this runs inside executeScan's post-completion phase where a failure must
// not affect a scan that has already succeeded and been recorded.
import crypto from "crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import { createOpsgenieAlert, createPagerDutyIncident, resolveOpsgenieAlert, resolvePagerDutyIncident } from "./oncallIntegrations";
import { ticketHostOf } from "./ticketLinks";
import { revealSecrets } from "./credentialEncryption";
import type { ScanReport } from "./scanReport";

type OncallIntegrationRow = {
  provider: "pagerduty" | "opsgenie";
  pagerduty_routing_key: string | null;
  opsgenie_api_key: string | null;
  region: "us" | "eu" | null;
};

/**
 * Deterministic dedup_key (PagerDuty) / alias (Opsgenie) for one owner's
 * finding on one host. Same inputs always produce the same key — that's the
 * whole mechanism this module relies on to resolve later without a ledger.
 * Prefixed so a key showing up in a PagerDuty/Opsgenie UI is recognisable as
 * coming from Hebrides Cyber.
 */
export function computeOncallDedupKey(ownerId: string, targetHost: string, checkId: string): string {
  const hash = crypto.createHash("sha256").update(`${ownerId}:${targetHost}:${checkId}`).digest("hex").slice(0, 40);
  return `hc-${hash}`;
}

async function fetchOncallIntegrations(supabaseAdmin: SupabaseClient, ownerId: string): Promise<OncallIntegrationRow[]> {
  const { data } = await supabaseAdmin
    .from("ticket_integrations")
    .select("provider, pagerduty_routing_key, opsgenie_api_key, region")
    .eq("owner", ownerId)
    .in("provider", ["pagerduty", "opsgenie"]);
  // Keys are stored encrypted (legacy plaintext passes through). One that can't
  // be decrypted — key missing or rotated — is skipped, never sent as-is.
  const rows = (data as OncallIntegrationRow[] | null) ?? [];
  const usable: OncallIntegrationRow[] = [];
  for (const row of rows) {
    const revealed = revealSecrets(row, ["pagerduty_routing_key", "opsgenie_api_key"]);
    if (revealed) usable.push(revealed);
    else console.error(`[oncallAlerts] Could not decrypt the ${row.provider} key for owner ${ownerId}; skipping it.`);
  }
  return usable;
}

function siteUrl(): string {
  return process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
}

/**
 * Opens a PagerDuty incident / Opsgenie alert for every new critical finding
 * in this report, for every pagerduty/opsgenie integration this owner has
 * configured (an owner can have both — fires to both). A finding the owner
 * has triaged (accepted / false positive / snoozed) never pages anyone.
 */
export async function triggerOncallAlerts(supabaseAdmin: SupabaseClient, ownerId: string, report: ScanReport): Promise<void> {
  try {
    const newCriticalFindings = report.findings.filter((f) => f.status === "new" && f.severity === "critical" && !f.triage);
    if (newCriticalFindings.length === 0) return;

    const integrations = await fetchOncallIntegrations(supabaseAdmin, ownerId);
    if (integrations.length === 0) return;

    const targetHost = ticketHostOf(report.target_url);
    const detailsUrl = `${siteUrl()}/dashboard/scans/${report.scan_id}`;

    for (const finding of newCriticalFindings) {
      if (!finding.check_id) continue; // no stable identity to dedup/resolve against
      const dedupKey = computeOncallDedupKey(ownerId, targetHost, finding.check_id);

      for (const integration of integrations) {
        if (integration.provider === "pagerduty") {
          if (!integration.pagerduty_routing_key) continue;
          const result = await createPagerDutyIncident(integration.pagerduty_routing_key, {
            dedupKey,
            summary: finding.title,
            severity: finding.severity,
            sourceUrl: report.target_url,
            detailsUrl,
          });
          if (!result.ok) {
            console.error(`[oncallAlerts] PagerDuty trigger failed for owner ${ownerId}, scan ${report.scan_id}, check ${finding.check_id}: ${result.error}`);
          }
        } else {
          if (!integration.opsgenie_api_key) continue;
          const result = await createOpsgenieAlert(integration.opsgenie_api_key, integration.region ?? "us", {
            alias: dedupKey,
            message: finding.title,
            description: finding.detail,
            priority: finding.severity,
            sourceUrl: report.target_url,
          });
          if (!result.ok) {
            console.error(`[oncallAlerts] Opsgenie trigger failed for owner ${ownerId}, scan ${report.scan_id}, check ${finding.check_id}: ${result.error}`);
          }
        }
      }
    }
  } catch (err) {
    console.error(`[oncallAlerts] triggerOncallAlerts threw for scan ${report.scan_id}:`, (err as Error).message);
  }
}

/**
 * Resolves the PagerDuty incident / Opsgenie alert for every fixed finding
 * in this report (any severity — see module header for why resolving a
 * never-triggered key is harmless), for every configured integration.
 */
export async function resolveOncallAlerts(supabaseAdmin: SupabaseClient, ownerId: string, report: ScanReport): Promise<void> {
  try {
    const fixedFindings = (report.fixed_findings ?? []).filter((f): f is typeof f & { check_id: string } => Boolean(f.check_id));
    if (fixedFindings.length === 0) return;

    const integrations = await fetchOncallIntegrations(supabaseAdmin, ownerId);
    if (integrations.length === 0) return;

    const targetHost = ticketHostOf(report.target_url);

    for (const finding of fixedFindings) {
      const dedupKey = computeOncallDedupKey(ownerId, targetHost, finding.check_id);

      for (const integration of integrations) {
        if (integration.provider === "pagerduty") {
          if (!integration.pagerduty_routing_key) continue;
          const ok = await resolvePagerDutyIncident(integration.pagerduty_routing_key, dedupKey);
          if (!ok) {
            console.error(`[oncallAlerts] PagerDuty resolve failed for owner ${ownerId}, scan ${report.scan_id}, check ${finding.check_id}`);
          }
        } else {
          if (!integration.opsgenie_api_key) continue;
          const ok = await resolveOpsgenieAlert(integration.opsgenie_api_key, integration.region ?? "us", dedupKey);
          if (!ok) {
            console.error(`[oncallAlerts] Opsgenie resolve failed for owner ${ownerId}, scan ${report.scan_id}, check ${finding.check_id}`);
          }
        }
      }
    }
  } catch (err) {
    console.error(`[oncallAlerts] resolveOncallAlerts threw for scan ${report.scan_id}:`, (err as Error).message);
  }
}

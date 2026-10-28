// E-66: persistence + resolution for DMARC aggregate reports. The pure parsing
// lives in dmarcAggregate.ts; this module turns a parsed report into a stored
// row and resolves the per-owner ingest token. Kept separate from the route so
// the mapping and token resolution are unit-testable without HTTP.
import type { SupabaseClient } from "@supabase/supabase-js";
import { createHash } from "node:crypto";
import type { DmarcAggregateReport } from "./dmarcAggregate";

export type DmarcReportRowInsert = {
  owner: string;
  domain: string;
  org_name: string;
  report_id: string;
  date_begin: string | null;
  date_end: string | null;
  total_messages: number;
  passing_messages: number;
  failing_messages: number;
  rows: DmarcAggregateReport["rows"];
};

/**
 * Maps a parsed report to a dmarc_reports insert for `owner`. A missing
 * report_id is replaced with a deterministic synthetic id (hash of
 * org+domain+dates+body-shape) so re-POSTing the same report still hits the
 * UNIQUE(owner, domain, report_id) idempotency constraint. `fallbackDomain` is
 * used when the report omits its policy domain (rare but seen).
 */
export function toReportInsert(
  owner: string,
  report: DmarcAggregateReport,
  fallbackDomain: string,
): DmarcReportRowInsert {
  const domain = (report.domain ?? fallbackDomain).toLowerCase();
  const reportId =
    report.reportId ??
    createHash("sha256")
      .update(`${report.orgName}|${domain}|${report.dateBegin}|${report.dateEnd}|${report.totalMessages}`)
      .digest("hex")
      .slice(0, 32);
  return {
    owner,
    domain,
    org_name: report.orgName,
    report_id: reportId,
    date_begin: report.dateBegin ? new Date(report.dateBegin * 1000).toISOString() : null,
    date_end: report.dateEnd ? new Date(report.dateEnd * 1000).toISOString() : null,
    total_messages: report.totalMessages,
    passing_messages: report.passingMessages,
    failing_messages: report.failingMessages,
    rows: report.rows,
  };
}

/**
 * Resolves the owner for a DMARC ingest token. Returns null for an unknown or
 * empty token — the route answers 401 without revealing which. Service-role
 * client (the token table isn't readable without the owner's own JWT).
 */
export async function resolveIngestToken(
  supabaseAdmin: SupabaseClient,
  token: string | undefined | null,
): Promise<string | null> {
  if (!token || token.length < 16) return null;
  const { data } = await supabaseAdmin
    .from("dmarc_ingest_tokens")
    .select("owner")
    .eq("token", token)
    .maybeSingle();
  return (data?.owner as string | undefined) ?? null;
}

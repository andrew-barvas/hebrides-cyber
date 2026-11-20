// Breached email accounts in a Lookout report (next-10 task 5). The base
// scan's HaveIBeenPwned domain search (scanners/hibp.ts) already records, per
// site, which known breaches included addresses on that domain and how many.
// A report shows that from each site's latest scan by the period's end.
//
// Built dark: with no HIBP_API_KEY every scan records "not_configured" and
// the section is left out entirely. A domain HIBP hasn't verified yet shows
// as "not enabled", never as "no breaches" (rule 7). Only counts and breach
// names are used; individual addresses are never stored or shown.
import type { SupabaseClient } from "@supabase/supabase-js";
import type { HibpBreach, HibpResult } from "./scanners/hibp";

export const REPORT_SCAN_LOOKBACK = 200;
const BREACHES_PER_SITE = 10;

export type SiteBreaches =
  | { host: string; status: "checked"; affectedAliasCount: number; breaches: Array<Pick<HibpBreach, "name" | "title" | "breachDate" | "dataClasses" | "affectedAliasCount">> }
  | { host: string; status: "not_verified" };

export type ReportBreaches = { available: boolean; sites: SiteBreaches[] };

type ScanRow = { target_url: string; created_at: string; scan_results: Array<{ hibp: HibpResult | null }> | { hibp: HibpResult | null } | null };

const hostOf = (url: string) => {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
};

/** Pure: newest-first scans → one entry per site that HIBP has a view on. */
export function breachesFromScans(scans: readonly ScanRow[]): ReportBreaches {
  const seen = new Set<string>();
  const sites: SiteBreaches[] = [];
  for (const scan of scans) {
    const host = hostOf(scan.target_url);
    if (!host || seen.has(host)) continue;
    const result = Array.isArray(scan.scan_results) ? scan.scan_results[0] : scan.scan_results;
    const hibp = result?.hibp;
    if (!hibp) continue;
    // A site's latest scan decides: an error or not_configured there means
    // no current evidence, so an older scan's result isn't shown as current.
    seen.add(host);
    if (hibp.status === "checked") {
      const breaches = [...hibp.breaches]
        .sort((a, b) => (b.breachDate ?? "").localeCompare(a.breachDate ?? ""))
        .slice(0, BREACHES_PER_SITE)
        .map(({ name, title, breachDate, dataClasses, affectedAliasCount }) => ({ name, title, breachDate, dataClasses, affectedAliasCount }));
      sites.push({ host, status: "checked", affectedAliasCount: hibp.affectedAliasCount, breaches });
    } else if (hibp.status === "not_verified") {
      sites.push({ host, status: "not_verified" });
    }
  }
  return { available: sites.length > 0, sites: sites.sort((a, b) => a.host.localeCompare(b.host)) };
}

export async function loadReportBreaches(supabaseAdmin: SupabaseClient, customer: string, periodEnd: string): Promise<ReportBreaches> {
  try {
    const { data, error } = await supabaseAdmin
      .from("scans")
      .select("target_url, created_at, scan_results(hibp:results->hibp)")
      .eq("owner", customer)
      .eq("status", "completed")
      .lte("created_at", `${periodEnd}T23:59:59Z`)
      .order("created_at", { ascending: false })
      .limit(REPORT_SCAN_LOOKBACK);
    if (error) {
      console.error("[lookout-breaches] read failed:", error.message);
      return { available: false, sites: [] };
    }
    return breachesFromScans((data ?? []) as ScanRow[]);
  } catch {
    return { available: false, sites: [] };
  }
}

/** One sentence for the draft summary; "" when nothing was found. */
export function breachSummarySentence(section: ReportBreaches): string {
  const hit = section.sites.filter((s): s is Extract<SiteBreaches, { status: "checked" }> => s.status === "checked" && s.affectedAliasCount > 0);
  if (hit.length === 0) return "";
  const addresses = hit.reduce((n, s) => n + s.affectedAliasCount, 0);
  const latest = hit.flatMap((s) => s.breaches).sort((a, b) => (b.breachDate ?? "").localeCompare(a.breachDate ?? ""))[0];
  return `${addresses} email address${addresses === 1 ? "" : "es"} on your domain${hit.length === 1 ? "" : "s"} appear in known data breaches${latest ? `, most recently ${latest.title}${latest.breachDate ? ` (${latest.breachDate})` : ""}` : ""}; those passwords should be changed and multi-factor sign-in turned on.`;
}

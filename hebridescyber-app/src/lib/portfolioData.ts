// Gathers what renderPortfolioReportHtml needs for one account: its monitored
// sites, each site's latest completed scan (matched by hostname, the same
// convention as FleetOverview and findingLifecycle), the account's triage and
// its white-label branding. Server-only (service-role client).
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Finding } from "./scanners";
import type { ReportBranding } from "./executiveReport";
import { hostOf } from "./findingLifecycle";
import { buildTriageIndex, loadTriageForOwner } from "./findingTriage";
import type { PortfolioInput, PortfolioSiteInput } from "./portfolioReport";

/** Recent completed scans looked at to find each site's latest. */
const SCAN_LOOKBACK = 500;

export async function loadPortfolioInput(db: SupabaseClient, ownerId: string, now: Date = new Date()): Promise<PortfolioInput> {
  const [targets, scans, sub, triage] = await Promise.all([
    db.from("monitored_targets").select("target_url").eq("owner", ownerId),
    db.from("scans").select("id, target_url, created_at").eq("owner", ownerId).eq("status", "completed").order("created_at", { ascending: false }).limit(SCAN_LOOKBACK),
    db.from("subscriptions").select("brand_logo_url, brand_name").eq("owner", ownerId).maybeSingle(),
    loadTriageForOwner(db, ownerId),
  ]);
  if (targets.error) throw new Error(`Could not read monitored sites: ${targets.error.message}`);
  if (scans.error) throw new Error(`Could not read scans: ${scans.error.message}`);
  // Triage is an enhancement here, as in the executive report: a failed read means "nothing triaged".
  if (triage.error) console.error("[portfolio-report] triage load failed:", triage.error);

  // One row per site, by hostname: a site monitored twice (with and without a trailing slash) is one site.
  const sites = new Map<string, string>();
  for (const t of (targets.data ?? []) as { target_url: string }[]) {
    const host = hostOf(t.target_url);
    if (host && !sites.has(host)) sites.set(host, t.target_url);
  }

  const latest = new Map<string, { id: string; created_at: string }>();
  for (const s of (scans.data ?? []) as { id: string; target_url: string; created_at: string }[]) {
    const host = hostOf(s.target_url);
    if (host && sites.has(host) && !latest.has(host)) latest.set(host, s);
  }

  const ids = [...latest.values()].map((s) => s.id);
  const results = new Map<string, { score: number | null; findings: Finding[] }>();
  if (ids.length) {
    const { data, error } = await db.from("scan_results").select("scan_id, score, findings:results->findings").in("scan_id", ids);
    if (error) throw new Error(`Could not read scan results: ${error.message}`);
    for (const r of (data ?? []) as { scan_id: string; score: number | null; findings: Finding[] | null }[]) {
      results.set(r.scan_id, { score: typeof r.score === "number" ? r.score : null, findings: Array.isArray(r.findings) ? r.findings : [] });
    }
  }

  const siteInputs: PortfolioSiteInput[] = [...sites.entries()].map(([host, targetUrl]) => {
    const scan = latest.get(host);
    const result = scan ? results.get(scan.id) : undefined;
    return { targetUrl, scan: scan && result ? { id: scan.id, completedAt: scan.created_at, score: result.score, findings: result.findings } : null };
  });

  const brand = sub.data as { brand_logo_url?: string | null; brand_name?: string | null } | null;
  const branding: ReportBranding | undefined =
    brand && (brand.brand_logo_url || brand.brand_name) ? { logoUrl: brand.brand_logo_url ?? undefined, name: brand.brand_name ?? undefined } : undefined;

  return { sites: siteInputs, triage: buildTriageIndex(triage.rows, now), branding, now };
}

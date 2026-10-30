// Emerging-threat alerts — the I/O half: KEV/NVD/OSV lookups, the
// emerging_threat_alerts ledger (sql/migrations/045), and notifications. Run
// every 6 hours by src/scripts/check-emerging-threats.ts
// (.github/workflows/emerging-threats.yml). Matching logic is pure and lives
// in emergingThreats.ts.
//
// Rules this module keeps:
//   - A failed lookup is an error, never "not affected": an unreadable KEV
//     feed throws (the job exits non-zero); a failed NVD/OSV lookup skips that
//     CVE and is reported as an error, so the next run retries it.
//   - NVD not having analysed a CVE yet (no configurations, and no npm data
//     on OSV) is "pending", not an error and not "not affected" — retried
//     each run while the CVE is inside the KEV look-back window.
//   - notified_at is stamped only after at least one channel delivered the
//     alert. Only rows matched in this run are sent, so a stale row (the
//     site has since been upgraded) is never alerted on old evidence.
//   - Before migration 045 the ledger write fails with a missing-table error;
//     the run then stops quietly (migrationPending) without sending anything.
import type { SupabaseClient } from "@supabase/supabase-js";
import { isMissingSchemaError } from "./dbErrors";
import { escapeHtml, sendEmail } from "./email";
import {
  KEV_LOOKBACK_DAYS,
  SCAN_LOOKBACK_DAYS,
  buildCveTechRanges,
  latestScanPerHost,
  matchHost,
  osvNpmPackages,
  recentKevAdditions,
  type CveTechRanges,
  type KevAddition,
  type NvdCveRecord,
  type OsvVulnRecord,
  type ScanCandidate,
  type ThreatMatch,
} from "./emergingThreats";
import { sendTeamsThreatAlert } from "./msTeams";
import { planIncludes, plansFor } from "./planAccess";
import { emergingThreatSteps } from "./scanners/remediationText";
import { collectTechInventory } from "./scanners/techInventory";
import type { FingerprintResult } from "./scanners/fingerprint";
import type { WebAppResult } from "./scanners/webapp";
import { loadKev } from "./scanners/threatIntel";
import { sendSlackThreatAlert, type ThreatAlertItem } from "./slack";

export const NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
export const OSV_VULN_API = "https://api.osv.dev/v1/vulns";
const NVD_TIMEOUT_MS = 20_000;
const OSV_TIMEOUT_MS = 10_000;
const USER_AGENT = "HebridesCyberBot/1.0 (+https://www.hebridescyber.co.uk)";
/** NVD allows 5 requests per rolling 30 s without a key, 50 with one. */
export const NVD_DELAY_MS = { withoutKey: 6_500, withKey: 700 } as const;
/** One retry after NVD's rate limiter (403/429) or a 503. */
const NVD_RETRY_DELAY_MS = 30_000;
/** GHSA aliases followed per CVE — a CVE rarely has more than one or two. */
const MAX_GHSA_ALIASES = 5;
const MAX_SCANS_PER_OWNER = 500;

type Sleep = (ms: number) => Promise<void>;
const realSleep: Sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ---- Lookups ------------------------------------------------------------------

type Fetched<T> = { ok: true; value: T } | { ok: false; error: string };

export async function fetchNvdCve(cveId: string, apiKey: string | undefined, sleep: Sleep = realSleep): Promise<Fetched<NvdCveRecord | null>> {
  const url = `${NVD_CVE_API}?cveId=${encodeURIComponent(cveId)}`;
  const headers: Record<string, string> = { "User-Agent": USER_AGENT };
  if (apiKey) headers.apiKey = apiKey;
  try {
    let res = await fetch(url, { headers, signal: AbortSignal.timeout(NVD_TIMEOUT_MS) });
    if (res.status === 403 || res.status === 429 || res.status === 503) {
      await sleep(NVD_RETRY_DELAY_MS);
      res = await fetch(url, { headers, signal: AbortSignal.timeout(NVD_TIMEOUT_MS) });
    }
    if (!res.ok) return { ok: false, error: `NVD responded ${res.status} for ${cveId}` };
    const body = (await res.json()) as { vulnerabilities?: Array<{ cve?: NvdCveRecord }> };
    if (!Array.isArray(body?.vulnerabilities)) return { ok: false, error: `NVD response for ${cveId} had no vulnerabilities array` };
    return { ok: true, value: body.vulnerabilities[0]?.cve ?? null };
  } catch (err) {
    return { ok: false, error: `NVD lookup for ${cveId} failed: ${(err as Error).message}` };
  }
}

async function fetchOsvRecord(id: string): Promise<Fetched<OsvVulnRecord | null>> {
  try {
    const res = await fetch(`${OSV_VULN_API}/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(OSV_TIMEOUT_MS) });
    if (res.status === 404) return { ok: true, value: null }; // OSV doesn't know this id
    if (!res.ok) return { ok: false, error: `OSV responded ${res.status} for ${id}` };
    return { ok: true, value: (await res.json()) as OsvVulnRecord };
  } catch (err) {
    return { ok: false, error: `OSV lookup for ${id} failed: ${(err as Error).message}` };
  }
}

/**
 * OSV's record for the CVE plus its GHSA aliases. The CVE record itself
 * carries git ranges; the npm semver ranges live on the GitHub advisory.
 */
export async function fetchOsvRecords(cveId: string): Promise<Fetched<OsvVulnRecord[]>> {
  const cve = await fetchOsvRecord(cveId);
  if (!cve.ok) return cve;
  if (!cve.value) return { ok: true, value: [] };
  const records = [cve.value];
  const aliases = (cve.value.aliases ?? []).filter((a) => /^GHSA-/.test(a)).slice(0, MAX_GHSA_ALIASES);
  for (const alias of aliases) {
    const r = await fetchOsvRecord(alias);
    if (!r.ok) return r;
    if (r.value) records.push(r.value);
  }
  return { ok: true, value: records };
}

export type CveLookup =
  | { status: "ok"; ranges: CveTechRanges }
  | { status: "pending"; note: string }
  | { status: "error"; note: string };

export async function lookupCve(cveId: string, apiKey: string | undefined, sleep: Sleep = realSleep): Promise<CveLookup> {
  const nvd = await fetchNvdCve(cveId, apiKey, sleep);
  if (!nvd.ok) return { status: "error", note: nvd.error };
  const osv = await fetchOsvRecords(cveId);
  if (!osv.ok) return { status: "error", note: osv.error };
  const analysed = (nvd.value?.configurations?.length ?? 0) > 0;
  if (!analysed && osvNpmPackages(osv.value).size === 0) {
    return { status: "pending", note: `${cveId}: NVD has not published affected configurations yet` };
  }
  return { status: "ok", ranges: buildCveTechRanges(cveId, nvd.value, osv.value) };
}

// ---- Owners and scans --------------------------------------------------------------

export type OwnerContext = {
  ownerId: string;
  plan: string | null;
  status: string | null;
  isAdmin: boolean;
  slackWebhookUrl: string | null;
  teamsWebhookUrl: string | null;
};

type SubRow = { owner: string; plan: string | null; status: string | null; slack_webhook_url: string | null; ms_teams_webhook_url: string | null };
const SUB_SELECT = "owner, plan, status, slack_webhook_url, ms_teams_webhook_url";

/** Owners on an active paid plan, plus admins (who may have no subscription). */
export async function loadEligibleOwners(supabase: SupabaseClient): Promise<OwnerContext[]> {
  const [subs, admins] = await Promise.all([
    supabase.from("subscriptions").select(SUB_SELECT).eq("status", "active").in("plan", [...plansFor("basic")]),
    supabase.from("users").select("id").eq("is_admin", true),
  ]);
  if (subs.error) throw new Error(`Could not load subscriptions: ${subs.error.message}`);
  if (admins.error) throw new Error(`Could not load admins: ${admins.error.message}`);

  const owners = new Map<string, OwnerContext>();
  const toContext = (row: SubRow, isAdmin: boolean): OwnerContext => ({
    ownerId: row.owner,
    plan: row.plan,
    status: row.status,
    isAdmin,
    slackWebhookUrl: row.slack_webhook_url,
    teamsWebhookUrl: row.ms_teams_webhook_url,
  });
  const adminIds = new Set(((admins.data ?? []) as Array<{ id: string }>).map((a) => a.id));
  for (const row of (subs.data ?? []) as SubRow[]) owners.set(row.owner, toContext(row, adminIds.has(row.owner)));

  const adminsWithoutPaidPlan = [...adminIds].filter((id) => !owners.has(id));
  if (adminsWithoutPaidPlan.length > 0) {
    const { data, error } = await supabase.from("subscriptions").select(SUB_SELECT).in("owner", adminsWithoutPaidPlan);
    if (error) throw new Error(`Could not load admin subscriptions: ${error.message}`);
    const byOwner = new Map(((data ?? []) as SubRow[]).map((r) => [r.owner, r]));
    for (const id of adminsWithoutPaidPlan) {
      const row = byOwner.get(id) ?? { owner: id, plan: null, status: null, slack_webhook_url: null, ms_teams_webhook_url: null };
      owners.set(id, toContext(row, true));
    }
  }
  return [...owners.values()];
}

export type HostScan = { host: string; scanId: string; scannedAt: string; inventory: ReturnType<typeof collectTechInventory> };

/** Each host's latest completed scan within SCAN_LOOKBACK_DAYS, with what it saw. */
export async function loadLatestHostScans(supabase: SupabaseClient, ownerId: string, now: Date): Promise<HostScan[]> {
  const since = new Date(now.getTime() - SCAN_LOOKBACK_DAYS * 24 * 60 * 60 * 1000).toISOString();
  const { data: scans, error } = await supabase
    .from("scans")
    .select("id, target_url, created_at")
    .eq("owner", ownerId)
    .eq("status", "completed")
    .gte("created_at", since)
    .order("created_at", { ascending: false })
    .limit(MAX_SCANS_PER_OWNER);
  if (error) throw new Error(`Could not load scans: ${error.message}`);

  const latest = latestScanPerHost((scans ?? []) as ScanCandidate[]);
  if (latest.size === 0) return [];
  const ids = [...latest.values()].map((s) => s.id);
  const { data: rows, error: resultsError } = await supabase.from("scan_results").select("scan_id, results").in("scan_id", ids);
  if (resultsError) throw new Error(`Could not load scan results: ${resultsError.message}`);

  type ResultRow = { scan_id: string; results: { fingerprint?: FingerprintResult; webapp?: WebAppResult } | null };
  const byScan = new Map(((rows ?? []) as ResultRow[]).map((r) => [r.scan_id, r.results]));
  const out: HostScan[] = [];
  for (const [host, scan] of latest) {
    const results = byScan.get(scan.id);
    if (!results) continue; // completed without a stored result — nothing to evidence
    out.push({ host, scanId: scan.id, scannedAt: scan.created_at, inventory: collectTechInventory(results.fingerprint, results.webapp) });
  }
  return out;
}

// ---- Notification content ------------------------------------------------------------

export type AlertItem = { host: string; scanId: string; scannedAt: string; match: ThreatMatch; kev: KevAddition };

const formatDate = (iso: string) => {
  const d = new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
};

/** Why we think this site is (or may be) affected — one plain sentence. */
export function evidenceSentence(item: AlertItem): string {
  const { match, host } = item;
  const scanned = formatDate(item.scannedAt);
  const seen = match.detectedVersion ? `${match.product} ${match.detectedVersion}` : match.product;
  switch (match.reason) {
    case "version_in_range":
      return `Our latest scan of ${host} (${scanned}) saw ${seen}, which is inside the version range listed as vulnerable.`;
    case "version_unknown":
      return `Our latest scan of ${host} (${scanned}) saw ${match.product}, but we can't see which version it runs, so we can't tell whether you're affected. Please check it.`;
    case "partial_version":
      return `Our latest scan of ${host} (${scanned}) saw ${seen}, but not the exact release, and some ${match.detectedVersion}.x releases are affected. Please check your exact version.`;
    case "distro_packaged":
      return `Our latest scan of ${host} (${scanned}) saw ${seen} installed from ${match.packagedBy ?? "a Linux distribution"}'s packages. That version number is in the vulnerable range, but distributions often fix vulnerabilities without changing it, so please check your distribution's advisory.`;
    case "platform_specific":
      return `Our latest scan of ${host} (${scanned}) saw ${seen}, which is in the vulnerable range, but this vulnerability only affects particular setups (for example a specific operating system) that we can't see from outside. Please check whether yours matches.`;
  }
}

export function buildThreatAlertEmail(items: AlertItem[], siteUrl: string): { subject: string; html: string } {
  const first = items[0];
  const subject =
    items.length === 1
      ? first.match.tier === "affected"
        ? `Actively exploited: ${first.kev.cveId} affects ${first.match.product} on ${first.host}`
        : `Check ${first.match.product} on ${first.host}: ${first.kev.cveId} is being actively exploited`
      : `${items.length} newly exploited vulnerabilities may affect your sites`;

  const sections = items
    .map((item) => {
      const { kev, match } = item;
      const heading = `${kev.cveId}${kev.vulnerabilityName ? `: ${kev.vulnerabilityName}` : ""}`;
      const badge =
        match.tier === "affected"
          ? `<span style="color:#b91c1c;font-weight:600;">Affected</span>`
          : `<span style="color:#b45309;font-weight:600;">Possibly affected — check your version</span>`;
      const why =
        `CISA added this to its Known Exploited Vulnerabilities catalog on ${formatDate(kev.dateAdded)}: attackers are actively exploiting it now` +
        (kev.ransomware ? ", including in ransomware campaigns." : ".");
      const steps = emergingThreatSteps(match.product, match.reason, match.packagedBy)
        .map((s) => `<li style="margin:0 0 4px;">${escapeHtml(s)}</li>`)
        .join("");
      const cve = encodeURIComponent(kev.cveId);
      return `
      <div style="border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin:0 0 16px;">
        <p style="margin:0 0 4px;font-size:12px;color:#4b5563;">${escapeHtml(item.host)} · ${badge}</p>
        <h3 style="margin:0 0 8px;font-size:16px;">${escapeHtml(heading)}</h3>
        <p style="margin:0 0 8px;font-size:14px;line-height:1.5;">${escapeHtml(evidenceSentence(item))}</p>
        <p style="margin:0 0 8px;font-size:14px;line-height:1.5;"><strong>Why it matters:</strong> ${escapeHtml(why)}</p>
        <p style="margin:0 0 4px;font-size:14px;"><strong>What to do:</strong></p>
        <ol style="margin:0 0 8px;padding-left:20px;font-size:14px;line-height:1.5;">${steps}</ol>
        <p style="margin:0;font-size:13px;">
          <a href="${siteUrl}/dashboard/scans/${encodeURIComponent(item.scanId)}">Latest report for ${escapeHtml(item.host)}</a> ·
          <a href="https://nvd.nist.gov/vuln/detail/${cve}">Advisory (NVD)</a> ·
          <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${cve}">CISA catalog entry</a>
        </p>
      </div>`;
    })
    .join("");

  const html = `
    <div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:600px;margin:0 auto;color:#111827;">
      <h2 style="margin:0 0 8px;font-size:20px;">Newly exploited vulnerability alert</h2>
      <p style="margin:0 0 16px;color:#4b5563;font-size:14px;line-height:1.5;">
        We compare every vulnerability CISA newly confirms as exploited with the software and versions
        your latest scans saw. ${items.length === 1 ? "This one matches" : "These match"} what we found on your ${items.length === 1 ? "site" : "sites"}.
      </p>
      ${sections}
      <p style="margin:16px 0 0;color:#9ca3af;font-size:12px;">
        You get one alert per vulnerability per site. We only alert when a scan shows the affected product;
        "possibly affected" means we saw the product but couldn't confirm its exact version.
      </p>
    </div>
  `;
  return { subject, html };
}

// ---- The run -----------------------------------------------------------------------

export type RunOptions = {
  dryRun?: boolean;
  now?: Date;
  nvdApiKey?: string;
  siteUrl?: string;
  sleep?: Sleep;
  log?: (line: string) => void;
};

export type RunSummary = {
  kevAdditions: number;
  cvesEvaluated: string[];
  cvesPending: string[];
  ownersChecked: number;
  hostsChecked: number;
  matches: Array<AlertItem & { ownerId: string }>;
  notified: number;
  migrationPending: boolean;
  errors: string[];
};

/** Which channels an owner gets: email on every paid plan; Slack/Teams on Pro/Agency (admins exempt). */
export function channelsFor(owner: OwnerContext): { slack: boolean; teams: boolean } {
  const chatPlan = owner.isAdmin || (owner.status === "active" && planIncludes(owner.plan, "pro"));
  return { slack: chatPlan && Boolean(owner.slackWebhookUrl), teams: chatPlan && Boolean(owner.teamsWebhookUrl) };
}

async function deliver(
  supabase: SupabaseClient,
  owner: OwnerContext,
  items: AlertItem[],
  siteUrl: string
): Promise<{ delivered: boolean; errors: string[] }> {
  const errors: string[] = [];
  let delivered = false;

  const { data: user } = await supabase.from("users").select("email").eq("id", owner.ownerId).maybeSingle();
  if (user?.email) {
    const { subject, html } = buildThreatAlertEmail(items, siteUrl);
    const sent = await sendEmail({ to: user.email as string, subject, html });
    if (sent.ok) delivered = true;
    else errors.push(`email to owner ${owner.ownerId} failed: ${sent.error}`);
  } else {
    errors.push(`owner ${owner.ownerId} has no email address on file`);
  }

  const chatItems: ThreatAlertItem[] = items.map((i) => ({
    host: i.host,
    cveId: i.kev.cveId,
    vulnerabilityName: i.kev.vulnerabilityName,
    product: i.match.product,
    detectedVersion: i.match.detectedVersion,
    tier: i.match.tier,
    reportUrl: `${siteUrl}/dashboard/scans/${encodeURIComponent(i.scanId)}`,
  }));
  const channels = channelsFor(owner);
  if (channels.slack) {
    try {
      await sendSlackThreatAlert(owner.slackWebhookUrl!, chatItems, siteUrl);
      delivered = true;
    } catch (err) {
      errors.push(`Slack alert for owner ${owner.ownerId} failed: ${(err as Error).message}`);
    }
  }
  if (channels.teams) {
    try {
      await sendTeamsThreatAlert(owner.teamsWebhookUrl!, chatItems, siteUrl);
      delivered = true;
    } catch (err) {
      errors.push(`Teams alert for owner ${owner.ownerId} failed: ${(err as Error).message}`);
    }
  }
  return { delivered, errors };
}

export async function runEmergingThreatCheck(supabase: SupabaseClient, opts: RunOptions = {}): Promise<RunSummary> {
  const now = opts.now ?? new Date();
  const sleep = opts.sleep ?? realSleep;
  const log = opts.log ?? (() => {});
  const siteUrl = opts.siteUrl ?? process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
  const summary: RunSummary = {
    kevAdditions: 0,
    cvesEvaluated: [],
    cvesPending: [],
    ownersChecked: 0,
    hostsChecked: 0,
    matches: [],
    notified: 0,
    migrationPending: false,
    errors: [],
  };

  const kev = await loadKev(now.getTime());
  if (!kev) throw new Error("CISA KEV feed could not be read — nothing was checked");
  const additions = recentKevAdditions(kev, now, KEV_LOOKBACK_DAYS);
  summary.kevAdditions = additions.length;
  log(`KEV: ${additions.length} addition(s) in the last ${KEV_LOOKBACK_DAYS} days.`);
  if (additions.length === 0) return summary;

  const delay = opts.nvdApiKey ? NVD_DELAY_MS.withKey : NVD_DELAY_MS.withoutKey;
  const evaluated: Array<{ kev: KevAddition; ranges: CveTechRanges }> = [];
  for (const [i, addition] of additions.entries()) {
    if (i > 0) await sleep(delay);
    const result = await lookupCve(addition.cveId, opts.nvdApiKey, sleep);
    if (result.status === "ok") {
      evaluated.push({ kev: addition, ranges: result.ranges });
      summary.cvesEvaluated.push(addition.cveId);
    } else if (result.status === "pending") {
      summary.cvesPending.push(addition.cveId);
      log(`  pending: ${result.note}`);
    } else {
      summary.errors.push(result.note);
      log(`  skipped: ${result.note}`);
    }
  }
  if (evaluated.length === 0) return summary;
  const kevById = new Map(evaluated.map((e) => [e.kev.cveId, e.kev]));
  const cveRanges = evaluated.map((e) => e.ranges);

  const owners = await loadEligibleOwners(supabase);
  for (const owner of owners) {
    summary.ownersChecked++;
    let hosts: HostScan[];
    try {
      hosts = await loadLatestHostScans(supabase, owner.ownerId, now);
    } catch (err) {
      summary.errors.push(`owner ${owner.ownerId}: ${(err as Error).message}`);
      continue;
    }
    summary.hostsChecked += hosts.length;

    const items: AlertItem[] = [];
    for (const h of hosts) {
      for (const match of matchHost(h.inventory, cveRanges)) {
        items.push({ host: h.host, scanId: h.scanId, scannedAt: h.scannedAt, match, kev: kevById.get(match.cveId)! });
      }
    }
    if (items.length === 0) continue;
    summary.matches.push(...items.map((i) => ({ ...i, ownerId: owner.ownerId })));
    if (opts.dryRun) continue;

    // matched_at and notified_at are deliberately absent: the first keeps its
    // insert default, the second must never be cleared by a re-match.
    const rows = items.map((i) => ({
      owner: owner.ownerId,
      target_host: i.host,
      cve_id: i.kev.cveId,
      confidence: i.match.tier,
      product: i.match.product,
      detected_version: i.match.detectedVersion,
      kev_date_added: i.kev.dateAdded,
      scan_id: i.scanId,
    }));
    const { data: saved, error } = await supabase
      .from("emerging_threat_alerts")
      .upsert(rows, { onConflict: "owner,target_host,cve_id" })
      .select("id, target_host, cve_id, notified_at");
    if (error) {
      if (isMissingSchemaError(error)) {
        summary.migrationPending = true;
        log("emerging_threat_alerts does not exist yet (migration 045 pending) — nothing recorded or sent.");
        return summary;
      }
      summary.errors.push(`owner ${owner.ownerId}: could not record matches: ${error.message}`);
      continue;
    }

    const unsent = new Map(
      ((saved ?? []) as Array<{ id: string; target_host: string; cve_id: string; notified_at: string | null }>)
        .filter((r) => r.notified_at === null)
        .map((r) => [`${r.target_host}|${r.cve_id}`, r.id])
    );
    const toSend = items.filter((i) => unsent.has(`${i.host}|${i.kev.cveId}`));
    if (toSend.length === 0) continue;

    const { delivered, errors } = await deliver(supabase, owner, toSend, siteUrl);
    summary.errors.push(...errors);
    if (!delivered) continue; // left unstamped: the next run retries

    const ids = toSend.map((i) => unsent.get(`${i.host}|${i.kev.cveId}`)!);
    const { error: stampError } = await supabase.from("emerging_threat_alerts").update({ notified_at: now.toISOString() }).in("id", ids);
    if (stampError) summary.errors.push(`owner ${owner.ownerId}: delivered but could not mark as notified: ${stampError.message}`);
    else summary.notified += ids.length;
  }
  return summary;
}

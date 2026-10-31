// Attack-surface change alerts, sent after each completed scan
// (scanExecution.ts Phase 2, after syncAssetInventory has recorded what this
// scan saw). Two kinds of change:
//
//   1. New hostnames: names under the site's domain whose first certificate
//      in Certificate Transparency logs was issued recently. A certificate
//      for a subdomain nobody knew about is the classic sign of a forgotten
//      service, or of someone else using the domain.
//   2. Changes to the domain's NS, MX, SPF and DMARC records, compared with
//      dns_snapshots. An unexpected change can mean a hijacked domain,
//      redirected mail or broken email authentication.
//
// Rules this module keeps:
//   - "New" needs evidence. A hostname missing from asset_inventory isn't
//     new: the sources are partial (crt.sh is capped at the 50 most recently
//     certified names and can be down; Subfinder's passive sources vary run
//     to run). A hostname is reported only when this scan's crt.sh data shows
//     its earliest certificate was issued since the previous scan of the site,
//     or within NEW_HOSTNAME_WINDOW_DAYS of when we first saw it. Every other
//     unreported row is marked as known without an alert. When crt.sh
//     couldn't be read there is no evidence either way, so rows stay pending
//     for a later scan to decide.
//   - The domain is scanners/registrableDomain.ts's ownerDomain (the full
//     Public Suffix List, private suffixes included), so mysite.github.io is
//     watched as itself, not as github.io. Hostnames outside it are never
//     reported.
//   - A failed DNS lookup is "unknown", never "the record is gone": only
//     ENODATA/ENOTFOUND mean absent. An unknown field keeps its stored value
//     and is never a change. dns.ts can't be reused for this: it treats a
//     failed lookup as "no record". A field's first answer is its baseline,
//     so the first scan, or a field that couldn't be read until now, never
//     triggers an alert.
//   - Each change is claimed before it is sent (notified_at set, or the
//     snapshot advanced only if nobody else advanced it first), so two scans
//     of www and apex finishing together can't both send it. If no channel
//     delivers, the claim is released and the next scan retries.
//   - Owners without an alerting plan get nothing, but their baselines still
//     advance, so upgrading doesn't replay months of old changes.
//   - Before migration 049 every read fails with a missing-schema error and
//     this quietly does nothing. It never throws: a scan is already complete
//     by the time this runs.
import { Resolver } from "node:dns/promises";
import type { SupabaseClient } from "@supabase/supabase-js";
import { isMissingSchemaError } from "./dbErrors";
import { escapeHtml, sendEmail } from "./email";
import { channelsFor, type OwnerContext } from "./emergingThreatAlerts";
import { sendTeamsNotice } from "./msTeams";
import { planIncludes } from "./planAccess";
import type { ReconResult } from "./scanners/recon";
import { isWithinDomain, ownerDomain } from "./scanners/registrableDomain";
import { sendSlackNotice } from "./slack";

/** Hostnames listed in one alert; the rest are counted. */
export const MAX_LISTED_HOSTNAMES = 20;
/** A hostname first certified this recently is new, even on a site's first scan. */
export const NEW_HOSTNAME_WINDOW_DAYS = 14;
/** Unreported rows read per page, and at most per scan (the rest wait for the next one). */
const PENDING_PAGE = 1_000;
const MAX_PENDING_HOSTNAMES = 10_000;
/** Hostnames per update request, keeping the request URL short. */
const STAMP_CHUNK = 100;
const DAY_MS = 24 * 60 * 60 * 1000;

/** The domain to watch for `host`, from the full Public Suffix List; null for IPs and bare suffixes. */
export function monitoredDomain(host: string): string | null {
  return ownerDomain(host);
}

// ---- DNS ----------------------------------------------------------------------

export type DnsResolver = {
  resolveNs(name: string): Promise<string[]>;
  resolveMx(name: string): Promise<Array<{ priority: number; exchange: string }>>;
  resolveTxt(name: string): Promise<string[][]>;
};

export type DnsField = "ns" | "mx" | "spf" | "dmarc";
export const DNS_FIELDS: readonly DnsField[] = ["ns", "mx", "spf", "dmarc"];

/** What a domain publishes. null = no such record. */
export type DnsValues = { ns: string[] | null; mx: string[] | null; spf: string | null; dmarc: string | null };
/** One lookup round. undefined = the lookup failed, so the value is unknown. */
export type DnsObservation = { [K in DnsField]: DnsValues[K] | undefined };
/** A stored snapshot: values are only meaningful for the fields in `known`. */
export type DnsSnapshot = { values: DnsValues; known: DnsField[] };

/** NXDOMAIN and "no records of this type": an answer, not a failure. */
const ABSENT_CODES = new Set(["ENODATA", "ENOTFOUND"]);

async function lookup<T>(run: () => Promise<T>, absent: T): Promise<T | undefined> {
  try {
    return await run();
  } catch (err) {
    return ABSENT_CODES.has((err as NodeJS.ErrnoException).code ?? "") ? absent : undefined;
  }
}

const hostName = (h: string) => h.trim().toLowerCase().replace(/\.$/, "") || ".";
const sortedOrNull = (values: string[]) => (values.length > 0 ? [...new Set(values)].sort() : null);
const collapse = (s: string) => s.replace(/\s+/g, " ").trim();

/** The TXT records starting with `prefix` (case-insensitive), chunks joined, one string. */
function txtValue(records: string[][], prefix: RegExp): string | null {
  const matching = records.map((chunks) => collapse(chunks.join(""))).filter((r) => prefix.test(r));
  return matching.length > 0 ? [...new Set(matching)].sort().join(" | ") : null;
}

export async function observeDns(domain: string, resolver: DnsResolver): Promise<DnsObservation> {
  const [ns, mx, txt, dmarcTxt] = await Promise.all([
    lookup(() => resolver.resolveNs(domain), []),
    lookup(() => resolver.resolveMx(domain), []),
    lookup(() => resolver.resolveTxt(domain), []),
    lookup(() => resolver.resolveTxt(`_dmarc.${domain}`), []),
  ]);
  return {
    ns: ns === undefined ? undefined : sortedOrNull(ns.map(hostName)),
    mx: mx === undefined ? undefined : sortedOrNull(mx.map((r) => `${r.priority} ${hostName(r.exchange)}`)),
    spf: txt === undefined ? undefined : txtValue(txt, /^v=spf1(\s|$)/i),
    dmarc: dmarcTxt === undefined ? undefined : txtValue(dmarcTxt, /^v=DMARC1(\s|;|$)/i),
  };
}

export type DnsChange = { field: DnsField; before: string[] | string | null; after: string[] | string | null };

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const EMPTY_VALUES: DnsValues = { ns: null, mx: null, spf: null, dmarc: null };

/**
 * Compares this lookup with the stored snapshot. A field that answered
 * before and now is compared; a field answering for the first time becomes
 * its baseline without a change; a field that didn't answer keeps what was
 * stored. `next` is what to store (null when there is nothing to store yet),
 * `unanswered` the fields this lookup couldn't read.
 */
export function diffDns(
  previous: DnsSnapshot | null,
  observed: DnsObservation
): { changes: DnsChange[]; next: DnsSnapshot | null; unanswered: DnsField[] } {
  const values: DnsValues = { ...(previous?.values ?? EMPTY_VALUES) };
  const known = new Set(previous?.known ?? []);
  const changes: DnsChange[] = [];
  const unanswered: DnsField[] = [];
  for (const field of DNS_FIELDS) {
    const value = observed[field];
    if (value === undefined) {
      unanswered.push(field);
      continue;
    }
    if (known.has(field) && !same(values[field], value)) changes.push({ field, before: values[field], after: value } as DnsChange);
    (values as Record<DnsField, unknown>)[field] = value;
    known.add(field);
  }
  const next = known.size > 0 ? { values, known: DNS_FIELDS.filter((f) => known.has(f)) } : null;
  return { changes, next, unanswered };
}

const FIELD_LABELS: Record<DnsField, string> = {
  ns: "Name servers (NS)",
  mx: "Mail servers (MX)",
  spf: "SPF record",
  dmarc: "DMARC record",
};

const show = (v: string[] | string | null) => (v === null ? "none" : Array.isArray(v) ? v.join(", ") : v);

/** One plain sentence per change. */
export function describeDnsChange(change: DnsChange): string {
  const label = FIELD_LABELS[change.field];
  if (change.before === null) return `${label} added: ${show(change.after)}`;
  if (change.after === null) {
    return change.field === "ns"
      ? `${label} no longer found (was ${show(change.before)}): the domain may have expired or been deleted`
      : `${label} removed (was ${show(change.before)})`;
  }
  return `${label} changed from ${show(change.before)} to ${show(change.after)}`;
}

// ---- New hostnames ----------------------------------------------------------------

export type NewHostname = { name: string; firstCertificate: string };

/** crt.sh dates carry no zone; they are UTC. */
const certTime = (iso: string) => Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso}Z`);

/** Each hostname's earliest certificate date in this scan's crt.sh data. */
export function firstCertificates(recon: ReconResult | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (recon?.status !== "checked") return out;
  for (const s of recon.subdomains) {
    const first = s.firstNotBefore;
    if (first && Number.isFinite(certTime(first))) out.set(s.name.toLowerCase(), first);
  }
  return out;
}

export type PendingHostname = { name: string; firstSeenAt: string };

/**
 * Splits unreported hostnames into the ones with evidence they are new (in
 * the domain, not the scanned site itself, and first certified after
 * `since`, or within the window before we first saw the row, so one left
 * pending by a failed alert doesn't age out before it is retried) and the
 * rest.
 */
export function classifyHostnames(
  pending: PendingHostname[],
  firsts: Map<string, string>,
  domain: string | null,
  scannedHost: string,
  since: Date
): { report: NewHostname[]; known: string[] } {
  const report: NewHostname[] = [];
  const known: string[] = [];
  for (const { name, firstSeenAt } of pending) {
    const first = firsts.get(name.toLowerCase());
    const seen = Date.parse(firstSeenAt);
    const cutoff = Number.isFinite(seen) ? Math.min(since.getTime(), seen - NEW_HOSTNAME_WINDOW_DAYS * DAY_MS) : since.getTime();
    const isNew = domain && first && name.toLowerCase() !== scannedHost && isWithinDomain(name, domain) && certTime(first) > cutoff;
    if (isNew) report.push({ name, firstCertificate: first });
    else known.push(name);
  }
  report.sort((a, b) => certTime(b.firstCertificate) - certTime(a.firstCertificate) || a.name.localeCompare(b.name));
  return { report, known };
}

// ---- Message ------------------------------------------------------------------

export type ChangeSet = {
  site: string;
  newHostnames: NewHostname[];
  dnsChanges: DnsChange[];
  /** What found the change; decides the wording of the email. A scan is assumed when absent. */
  source?: "scan" | "sweep";
};

export function noticeTitle(c: ChangeSet): string {
  const hosts = c.newHostnames.length;
  if (hosts > 0 && c.dnsChanges.length > 0) return `New hostnames and DNS changes for ${c.site}`;
  if (hosts > 0) return `${hosts} new hostname${hosts === 1 ? "" : "s"} found for ${c.site}`;
  return `DNS records changed for ${c.site}`;
}

const formatDate = (iso: string) =>
  new Date(certTime(iso)).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
const hostLine = (h: NewHostname) => `${h.name} (first certificate ${formatDate(h.firstCertificate)})`;

const HOSTNAME_WHY =
  "Public certificate logs show a certificate issued for each of these names for the first time. A name you don't recognise can be a forgotten service, or someone else using your domain. Check each one is yours and still needed.";
const DNS_WHY =
  "If you didn't make these changes, check your domain registrar and DNS provider accounts now: changed name or mail servers can mean the domain was taken over or email is being redirected, and an SPF or DMARC change can stop your email being delivered or make it easier to fake.";

/** Plain lines for Slack/Teams (they escape them). */
export function noticeLines(c: ChangeSet): string[] {
  const lines: string[] = [];
  if (c.newHostnames.length > 0) {
    const listed = c.newHostnames.slice(0, MAX_LISTED_HOSTNAMES);
    lines.push(`New hostname${listed.length === 1 ? "" : "s"}: ${listed.map(hostLine).join(", ")}`);
    const more = c.newHostnames.length - listed.length;
    if (more > 0) lines.push(`…and ${more} more on the Assets page`);
    lines.push(HOSTNAME_WHY);
  }
  if (c.dnsChanges.length > 0) {
    lines.push(...c.dnsChanges.map(describeDnsChange));
    lines.push(DNS_WHY);
  }
  return lines;
}

export function buildAttackSurfaceEmail(c: ChangeSet, siteUrl: string): { subject: string; html: string } {
  const p = (text: string) => `<p style="margin:0 0 12px;font-size:14px;line-height:1.5;">${text}</p>`;
  const list = (items: string[]) =>
    `<ul style="margin:0 0 12px;padding-left:20px;font-size:14px;line-height:1.5;">${items.map((i) => `<li>${escapeHtml(i)}</li>`).join("")}</ul>`;

  let body = "";
  if (c.newHostnames.length > 0) {
    const listed = c.newHostnames.slice(0, MAX_LISTED_HOSTNAMES);
    const more = c.newHostnames.length - listed.length;
    body += `<h3 style="margin:16px 0 8px;font-size:16px;">New hostnames</h3>`;
    body += list(listed.map(hostLine));
    if (more > 0) body += p(`…and ${more} more, listed on the Assets page.`);
    body += p(escapeHtml(HOSTNAME_WHY));
  }
  if (c.dnsChanges.length > 0) {
    body += `<h3 style="margin:16px 0 8px;font-size:16px;">DNS changes</h3>`;
    body += list(c.dnsChanges.map(describeDnsChange));
    body += p(escapeHtml(DNS_WHY));
  }

  const html = `
    <div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:600px;margin:0 auto;color:#111827;">
      <h2 style="margin:0 0 8px;font-size:20px;">${escapeHtml(noticeTitle(c))}</h2>
      <p style="margin:0 0 8px;color:#4b5563;font-size:14px;line-height:1.5;">
        ${c.source === "sweep" ? `Our regular check of public certificate logs for ${escapeHtml(c.site)} found these changes.` : `Your latest scan of ${escapeHtml(c.site)} found these changes.`}
      </p>
      ${body}
      <p style="margin:16px 0 0;font-size:13px;"><a href="${siteUrl}/dashboard/assets">Open Assets</a></p>
      <p style="margin:16px 0 0;color:#9ca3af;font-size:12px;">
        We tell you about each new hostname and each DNS change once. A hostname counts as new when its first
        certificate was issued since your previous scan (or in the last ${NEW_HOSTNAME_WINDOW_DAYS} days). DNS records
        are compared with what we saw before, so your first scan of a site only records them.
      </p>
    </div>
  `;
  return { subject: noticeTitle(c), html };
}

// ---- The run ------------------------------------------------------------------

export type AttackSurfaceOptions = { resolver?: DnsResolver; now?: Date; siteUrl?: string };

export type AttackSurfaceResult = {
  /** Hostnames and DNS changes the owner was told about in this run. */
  reported: ChangeSet | null;
  /** Unreported hostnames marked as known without an alert (no evidence they are new, or no alerting plan). */
  silentlyRecorded: string[];
  /** crt.sh couldn't be read, so unreported hostnames were left for a later scan to decide. */
  hostnamesDeferred: boolean;
  /** DNS fields this run couldn't read (kept as they were, never a change). */
  unanswered: DnsField[];
  delivered: boolean;
  migrationPending: boolean;
  errors: string[];
};

let defaultResolver: DnsResolver | null = null;
function systemResolver(): DnsResolver {
  // Short timeouts: this runs after the scan, in line with the other
  // post-completion notifications.
  defaultResolver ??= new Resolver({ timeout: 5_000, tries: 2 });
  return defaultResolver;
}

type SnapshotRow = { ns: string[] | null; mx: string[] | null; spf: string | null; dmarc: string | null; known_fields: string[] | null; captured_at: string };

/** When the owner's previous completed scan of exactly this host started, or null. */
async function previousScanAt(supabase: SupabaseClient, ownerId: string, scanId: string, host: string): Promise<Date | null> {
  // Bounded to this host in the query (any scheme, optional port or path), so
  // other sites' scans can't crowd it out; the hostname is compared exactly below.
  const { data, error } = await supabase
    .from("scans")
    .select("target_url, created_at")
    .eq("owner", ownerId)
    .eq("status", "completed")
    .neq("id", scanId)
    .or(`target_url.ilike.*://${host},target_url.ilike.*://${host}/*,target_url.ilike.*://${host}:*`)
    .order("created_at", { ascending: false })
    .limit(20);
  if (error) throw new Error(`could not load earlier scans: ${error.message}`);
  for (const s of (data ?? []) as Array<{ target_url: string; created_at: string }>) {
    try {
      if (new URL(s.target_url).hostname.toLowerCase() === host) return new Date(s.created_at);
    } catch {
      // an unparseable stored URL is not this host
    }
  }
  return null;
}

async function loadOwner(supabase: SupabaseClient, ownerId: string): Promise<{ owner: OwnerContext; email: string | null; alerting: boolean }> {
  const [sub, user] = await Promise.all([
    supabase.from("subscriptions").select("plan, status, slack_webhook_url, ms_teams_webhook_url").eq("owner", ownerId).maybeSingle(),
    supabase.from("users").select("email, is_admin").eq("id", ownerId).maybeSingle(),
  ]);
  if (sub.error) throw new Error(`could not load the subscription: ${sub.error.message}`);
  if (user.error) throw new Error(`could not load the user: ${user.error.message}`);
  const s = sub.data as { plan: string | null; status: string | null; slack_webhook_url: string | null; ms_teams_webhook_url: string | null } | null;
  const u = user.data as { email: string | null; is_admin: boolean | null } | null;
  const owner: OwnerContext = {
    ownerId,
    plan: s?.plan ?? null,
    status: s?.status ?? null,
    isAdmin: Boolean(u?.is_admin),
    slackWebhookUrl: s?.slack_webhook_url ?? null,
    teamsWebhookUrl: s?.ms_teams_webhook_url ?? null,
  };
  const alerting = owner.isAdmin || (owner.status === "active" && planIncludes(owner.plan, "basic"));
  return { owner, email: u?.email ?? null, alerting };
}

async function deliver(owner: OwnerContext, email: string | null, changes: ChangeSet, siteUrl: string): Promise<{ delivered: boolean; errors: string[] }> {
  const errors: string[] = [];
  let delivered = false;

  if (email) {
    const { subject, html } = buildAttackSurfaceEmail(changes, siteUrl);
    const sent = await sendEmail({ to: email, subject, html });
    if (sent.ok) delivered = true;
    else errors.push(`email failed: ${sent.error}`);
  } else {
    errors.push("no email address on file");
  }

  const title = noticeTitle(changes);
  const lines = noticeLines(changes);
  const dashboardUrl = `${siteUrl}/dashboard/assets`;
  const channels = channelsFor(owner);
  if (channels.slack) {
    try {
      await sendSlackNotice(owner.slackWebhookUrl!, title, lines, dashboardUrl);
      delivered = true;
    } catch (err) {
      errors.push(`Slack failed: ${(err as Error).message}`);
    }
  }
  if (channels.teams) {
    try {
      await sendTeamsNotice(owner.teamsWebhookUrl!, title, lines, dashboardUrl);
      delivered = true;
    } catch (err) {
      errors.push(`Teams failed: ${(err as Error).message}`);
    }
  }
  return { delivered, errors };
}

const chunks = <T,>(items: T[]) => Array.from({ length: Math.ceil(items.length / STAMP_CHUNK) }, (_, i) => items.slice(i * STAMP_CHUNK, (i + 1) * STAMP_CHUNK));
const snapshotColumns = (s: DnsSnapshot) => ({ ...s.values, known_fields: s.known });

// ---- Shared by the scan alert and the standalone sweep alert ------------------------
// A hostname's row is the unit of "has the owner been told": notified_at null
// means pending, a timestamp means reported or deliberately recorded as known.
// Both paths read, claim and release rows the same way, so a scan and a sweep
// that finish together cannot both send the same alert.

/** Marks hostnames as known without an alert. Returns the first error message, or null. */
async function stampKnown(supabase: SupabaseClient, ownerId: string, names: string[], now: string): Promise<string | null> {
  for (const chunk of chunks(names)) {
    const { error } = await supabase.from("asset_inventory").update({ notified_at: now }).eq("owner", ownerId).is("notified_at", null).in("hostname", chunk);
    if (error) return error.message;
  }
  return null;
}

/**
 * Claims the hostnames this run will send: the update only succeeds for a row
 * still pending, so what comes back is exactly what this run won.
 */
async function claimHostnames(supabase: SupabaseClient, ownerId: string, report: NewHostname[], now: string): Promise<{ claimed: NewHostname[]; error: string | null }> {
  const claimed: NewHostname[] = [];
  for (const chunk of chunks(report)) {
    const { data, error } = await supabase
      .from("asset_inventory")
      .update({ notified_at: now })
      .eq("owner", ownerId)
      .is("notified_at", null)
      .in("hostname", chunk.map((h) => h.name))
      .select("hostname");
    if (error) return { claimed, error: error.message };
    const won = new Set(((data ?? []) as Array<{ hostname: string }>).map((r) => r.hostname));
    claimed.push(...chunk.filter((h) => won.has(h.name)));
  }
  return { claimed, error: null };
}

/** Gives claimed hostnames back (notified_at null) after a failed delivery, so the next run retries. Returns the error messages. */
async function releaseHostnames(supabase: SupabaseClient, ownerId: string, claimed: NewHostname[], now: string): Promise<string[]> {
  const errors: string[] = [];
  for (const chunk of chunks(claimed)) {
    const { error } = await supabase
      .from("asset_inventory")
      .update({ notified_at: null })
      .eq("owner", ownerId)
      .eq("notified_at", now)
      .in("hostname", chunk.map((h) => h.name));
    if (error) errors.push(error.message);
  }
  return errors;
}

export async function sendAttackSurfaceAlerts(
  supabase: SupabaseClient,
  ownerId: string,
  scanId: string,
  targetUrl: string,
  recon: ReconResult | undefined,
  opts: AttackSurfaceOptions = {}
): Promise<AttackSurfaceResult> {
  const result: AttackSurfaceResult = { reported: null, silentlyRecorded: [], hostnamesDeferred: false, unanswered: [], delivered: false, migrationPending: false, errors: [] };
  const fail = (message: string) => {
    result.errors.push(message);
    console.error(`[attackSurfaceMonitor] ${targetUrl}: ${message}`);
  };

  try {
    const nowDate = opts.now ?? new Date();
    const now = nowDate.toISOString();
    const siteUrl = opts.siteUrl ?? process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
    const host = new URL(targetUrl).hostname.toLowerCase();
    const domain = monitoredDomain(host);

    // Every hostname syncAssetInventory recorded for this site that hasn't been reported or marked known.
    const pending: PendingHostname[] = [];
    for (let from = 0; from < MAX_PENDING_HOSTNAMES; from += PENDING_PAGE) {
      const page = await supabase
        .from("asset_inventory")
        .select("hostname, first_seen_at")
        .eq("owner", ownerId)
        .eq("target_url", targetUrl)
        .is("notified_at", null)
        .order("hostname", { ascending: true })
        .range(from, from + PENDING_PAGE - 1);
      if (page.error) {
        if (isMissingSchemaError(page.error)) {
          result.migrationPending = true;
          return result;
        }
        throw new Error(`could not load unreported hostnames: ${page.error.message}`);
      }
      const rows = (page.data ?? []) as Array<{ hostname: string; first_seen_at: string }>;
      pending.push(...rows.map((r) => ({ name: r.hostname, firstSeenAt: r.first_seen_at })));
      if (rows.length < PENDING_PAGE) break;
    }
    if (pending.length >= MAX_PENDING_HOSTNAMES) console.warn(`[attackSurfaceMonitor] ${targetUrl}: over ${MAX_PENDING_HOSTNAMES} unreported hostnames; the rest wait for the next scan`);

    // The stored DNS snapshot, and this scan's lookup.
    let previous: { snapshot: DnsSnapshot; capturedAt: string } | null = null;
    let dns: ReturnType<typeof diffDns> | null = null;
    if (domain) {
      const snap = await supabase
        .from("dns_snapshots")
        .select("ns, mx, spf, dmarc, known_fields, captured_at")
        .eq("owner", ownerId)
        .eq("target_host", domain)
        .maybeSingle();
      if (snap.error) {
        if (isMissingSchemaError(snap.error)) {
          result.migrationPending = true;
          return result;
        }
        throw new Error(`could not load the DNS snapshot: ${snap.error.message}`);
      }
      const row = snap.data as SnapshotRow | null;
      if (row) {
        const known = (row.known_fields ?? []).filter((f): f is DnsField => (DNS_FIELDS as readonly string[]).includes(f));
        previous = { snapshot: { values: { ns: row.ns, mx: row.mx, spf: row.spf, dmarc: row.dmarc }, known }, capturedAt: row.captured_at };
      }
      dns = diffDns(previous?.snapshot ?? null, await observeDns(domain, opts.resolver ?? systemResolver()));
      result.unanswered = dns.unanswered;
      if (dns.unanswered.length > 0) console.warn(`[attackSurfaceMonitor] ${domain}: no answer for ${dns.unanswered.join(", ")}; kept as before`);
    }

    const { owner, email, alerting } = await loadOwner(supabase, ownerId);

    let hosts: { report: NewHostname[]; known: string[] } = { report: [], known: pending.map((p) => p.name) };
    const ctRead = recon?.status === "checked" && !recon.ctLookupFailed;
    if (alerting && pending.length > 0 && !ctRead) {
      // No certificate evidence either way: leave them for a scan that has it.
      hosts = { report: [], known: [] };
      result.hostnamesDeferred = true;
    } else if (alerting && pending.length > 0) {
      const prior = await previousScanAt(supabase, ownerId, scanId, host);
      const windowStart = new Date(nowDate.getTime() - NEW_HOSTNAME_WINDOW_DAYS * DAY_MS);
      const since = prior && prior < windowStart ? prior : windowStart;
      hosts = classifyHostnames(pending, firstCertificates(recon), domain, host, since);
    }

    // Hostnames without evidence they are new: known from now on, no alert.
    const stampError = await stampKnown(supabase, ownerId, hosts.known, now);
    if (stampError) fail(`could not mark hostnames as known: ${stampError}`);
    else result.silentlyRecorded = hosts.known;

    const dnsChanges = alerting ? (dns?.changes ?? []) : [];
    const writeSnapshot = async () => {
      if (!domain || !dns?.next || (previous && same(previous.snapshot, dns.next))) return;
      const { error } = await supabase
        .from("dns_snapshots")
        .upsert({ owner: ownerId, target_host: domain, ...snapshotColumns(dns.next), captured_at: now }, { onConflict: "owner,target_host" });
      if (error) fail(`could not save the DNS snapshot: ${error.message}`);
    };
    // No change to claim: store a baseline, a newly answered field, or a non-alerting owner's change.
    if (dnsChanges.length === 0) await writeSnapshot();
    if (hosts.report.length === 0 && dnsChanges.length === 0) return result;

    // Claim what this run will send, so a concurrent scan of the same domain can't send it too.
    const claim = await claimHostnames(supabase, ownerId, hosts.report, now);
    if (claim.error) fail(`could not claim new hostnames: ${claim.error}`);
    const claimedHosts = claim.claimed;
    let claimedDns: DnsChange[] = [];
    if (dnsChanges.length > 0 && previous && dns?.next) {
      const { data, error } = await supabase
        .from("dns_snapshots")
        .update({ ...snapshotColumns(dns.next), captured_at: now })
        .eq("owner", ownerId)
        .eq("target_host", domain)
        .eq("captured_at", previous.capturedAt)
        .select("target_host");
      if (error) fail(`could not claim the DNS change: ${error.message}`);
      else if ((data ?? []).length > 0) claimedDns = dnsChanges;
    }
    if (claimedHosts.length === 0 && claimedDns.length === 0) return result; // another scan got there first

    const changes: ChangeSet = { site: domain ?? host, newHostnames: claimedHosts, dnsChanges: claimedDns };
    const sent = await deliver(owner, email, changes, siteUrl);
    sent.errors.forEach(fail);
    if (sent.delivered) {
      result.delivered = true;
      result.reported = changes;
      return result;
    }

    // Nothing delivered: release the claims so the next scan retries.
    for (const message of await releaseHostnames(supabase, ownerId, claimedHosts, now)) fail(`could not release new hostnames for a retry: ${message}`);
    if (claimedDns.length > 0 && previous) {
      const { error } = await supabase
        .from("dns_snapshots")
        .update({ ...snapshotColumns(previous.snapshot), captured_at: previous.capturedAt })
        .eq("owner", ownerId)
        .eq("target_host", domain)
        .eq("captured_at", now);
      if (error) fail(`could not release the DNS change for a retry: ${error.message}`);
    }
    return result;
  } catch (err) {
    fail((err as Error).message);
    return result;
  }
}

// ---- Standalone EASM sweep ------------------------------------------------------------
// easmPipeline.ts finds new certificates every few hours, independent of the scan
// cadence. Before this, it only recorded them as pending rows and left the alert to
// the owner's next scan: up to a week away for a weekly plan. This sends the same
// new-hostname alert from the sweep, with the same rules as sendAttackSurfaceAlerts:
//   - Evidence first. A hostname is reported only when crt.sh shows its earliest
//     certificate is recent. When crt.sh could not be read (`ctRead` false) nothing is
//     decided and the rows stay pending: no evidence either way is not "not new".
//   - Claim, then send. The same atomic claim as the scan path, so a scan and a sweep
//     that finish together cannot both send it, and a failed delivery is released.
//   - Pending rows are found by owner and domain, NOT by target_url. Rows the EASM step
//     stored before it recorded the monitored URL carry https://<domain>, which no scan
//     of a www site ever matched; this picks them up instead of leaving them stuck.
// DNS changes are not checked here: they need the stored snapshot's claim logic and
// are left to the scan path.

export type SweepEvidence = {
  /** Each hostname's earliest certificate date, from this sweep's crt.sh read. */
  firstCertificates: Map<string, string>;
  /** crt.sh was read. False means the lookup failed and nothing may be concluded. */
  ctRead: boolean;
};

export type SweepAlertResult = {
  /** Hostnames the owner was told about in this run. */
  reported: ChangeSet | null;
  /** Pending hostnames marked as known without an alert (no evidence they are new, or no alerting plan). */
  silentlyRecorded: string[];
  /** crt.sh could not be read, so pending hostnames were left for a later run to decide. */
  hostnamesDeferred: boolean;
  delivered: boolean;
  migrationPending: boolean;
  errors: string[];
};

/** Not a real scan id: the sweep has no current scan to exclude when looking for the previous one. */
const NO_SCAN = "00000000-0000-0000-0000-000000000000";
/** Domains reach a PostgREST filter string, so anything but plain DNS characters is refused. */
const FILTER_SAFE_DOMAIN = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/;

export async function sendSweepHostnameAlerts(
  supabase: SupabaseClient,
  ownerId: string,
  targetUrl: string,
  evidence: SweepEvidence,
  opts: AttackSurfaceOptions = {}
): Promise<SweepAlertResult> {
  const result: SweepAlertResult = { reported: null, silentlyRecorded: [], hostnamesDeferred: false, delivered: false, migrationPending: false, errors: [] };
  const fail = (message: string) => {
    result.errors.push(message);
    console.error(`[attackSurfaceMonitor] sweep ${targetUrl}: ${message}`);
  };

  try {
    const nowDate = opts.now ?? new Date();
    const now = nowDate.toISOString();
    const siteUrl = opts.siteUrl ?? process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
    const host = new URL(targetUrl).hostname.toLowerCase();
    const domain = monitoredDomain(host);
    if (!domain || !FILTER_SAFE_DOMAIN.test(domain)) return result;

    // Every unreported hostname in the domain, whichever URL its row was stored under.
    const pending: PendingHostname[] = [];
    for (let from = 0; from < MAX_PENDING_HOSTNAMES; from += PENDING_PAGE) {
      const page = await supabase
        .from("asset_inventory")
        .select("hostname, first_seen_at")
        .eq("owner", ownerId)
        .is("notified_at", null)
        .or(`hostname.ilike.${domain},hostname.ilike.*.${domain}`)
        .order("hostname", { ascending: true })
        .range(from, from + PENDING_PAGE - 1);
      if (page.error) {
        if (isMissingSchemaError(page.error)) {
          result.migrationPending = true;
          return result;
        }
        throw new Error(`could not load unreported hostnames: ${page.error.message}`);
      }
      const rows = (page.data ?? []) as Array<{ hostname: string; first_seen_at: string }>;
      pending.push(...rows.map((r) => ({ name: r.hostname, firstSeenAt: r.first_seen_at })));
      if (rows.length < PENDING_PAGE) break;
    }
    if (pending.length === 0) return result;

    const { owner, email, alerting } = await loadOwner(supabase, ownerId);

    // No alerting plan: record them as known so an upgrade doesn't replay old hostnames.
    if (!alerting) {
      const names = pending.map((p) => p.name);
      const stampError = await stampKnown(supabase, ownerId, names, now);
      if (stampError) fail(`could not mark hostnames as known: ${stampError}`);
      else result.silentlyRecorded = names;
      return result;
    }

    // No certificate evidence either way: decide nothing, leave them pending.
    if (!evidence.ctRead) {
      result.hostnamesDeferred = true;
      return result;
    }

    const prior = await previousScanAt(supabase, ownerId, NO_SCAN, host);
    const windowStart = new Date(nowDate.getTime() - NEW_HOSTNAME_WINDOW_DAYS * DAY_MS);
    const since = prior && prior < windowStart ? prior : windowStart;
    const hosts = classifyHostnames(pending, evidence.firstCertificates, domain, host, since);

    const stampError = await stampKnown(supabase, ownerId, hosts.known, now);
    if (stampError) fail(`could not mark hostnames as known: ${stampError}`);
    else result.silentlyRecorded = hosts.known;
    if (hosts.report.length === 0) return result;

    const claim = await claimHostnames(supabase, ownerId, hosts.report, now);
    if (claim.error) fail(`could not claim new hostnames: ${claim.error}`);
    if (claim.claimed.length === 0) return result; // a scan got there first

    const changes: ChangeSet = { site: domain, newHostnames: claim.claimed, dnsChanges: [], source: "sweep" };
    const sent = await deliver(owner, email, changes, siteUrl);
    sent.errors.forEach(fail);
    if (sent.delivered) {
      result.delivered = true;
      result.reported = changes;
      return result;
    }

    // Nothing delivered: release the claims so the next run retries.
    for (const message of await releaseHostnames(supabase, ownerId, claim.claimed, now)) fail(`could not release new hostnames for a retry: ${message}`);
    return result;
  } catch (err) {
    fail((err as Error).message);
    return result;
  }
}

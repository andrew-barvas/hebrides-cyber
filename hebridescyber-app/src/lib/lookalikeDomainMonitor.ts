// Lookalike-domain / phishing monitoring, run periodically (not on every
// scan — see SWEEP_INTERVAL_DAYS below) from scanExecution.ts Phase 2,
// alongside attackSurfaceMonitor.ts's new-hostname/DNS-change alerts.
//
// For an owner's own domain (ownerDomain(host), the full Public Suffix
// List, same identity attackSurfaceMonitor.ts watches), this generates a
// small, bounded set of candidate domains one simple edit away — a
// character dropped, doubled, swapped for a visual lookalike, or
// transposed; a hyphen inserted; a different common top-level domain — and
// checks the real Certificate Transparency logs (crt.sh) for each one.
//
// A name match alone proves nothing: this never claims a candidate domain
// is malicious, only that a real TLS certificate has already been issued
// for it — strong, freely-available evidence it is registered and actively
// served, which is the standard setup for phishing or business-email-
// compromise against a brand. A candidate crt.sh has no record of (the
// common case — most permutations of any domain are unregistered) is
// never reported; neither is one where the lookup itself failed. No DNS
// resolution and no request is ever sent to the candidate domain itself —
// this only reads the public certificate-transparency record, exactly the
// data source recon.ts/subdomainCerts.ts/attackSurfaceMonitor.ts already
// depend on for the owner's own domain.
//
// Deliberately NOT dnstwist (the well-known real tool for this): dnstwist's
// value is in live DNS resolution of each candidate, which needs a worker
// with real DNS egress to verify — unlike the registry-based checks this
// session shipped elsewhere, that live behaviour could not be captured and
// verified from this sandbox (its DNS resolution is restricted, including
// for domains that definitely exist). crt.sh's exact-domain lookup is the
// same already-proven data source and endpoint this codebase already
// trusts for the owner's own domain, just queried with a different
// candidate string — no new binary, no new install step, fully testable
// against a known, already-used JSON shape.
//
// Rules this module keeps, matching attackSurfaceMonitor.ts:
//   - A candidate is only ever added to lookalike_domains once crt.sh shows
//     it is actually registered — the "not_found"/"error" cases produce no
//     row.
//   - Once a candidate is known (a row exists, reported or not) it is
//     never re-alerted — a phishing domain usually stays registered, so
//     re-finding it every sweep would be noise.
//   - A sweep is claimed (lookalike_domain_sweeps.swept_at) regardless of
//     whether anything was found, so a clean domain is still throttled
//     correctly next time.
//   - Each newly-found domain is claimed (notified_at set) before it is
//     sent, and released if nothing delivered, so two overlapping sweeps
//     of the same domain can't send it twice and a failed alert retries.
//   - Owners without an alerting plan are skipped entirely, before any
//     crt.sh query — unlike attackSurfaceMonitor.ts's asset-inventory
//     baseline (nearly free, built from data the scan gathers anyway),
//     a sweep here costs real external requests with no one to tell.
//   - Before migration 053 this quietly does nothing. It never throws: a
//     scan is already complete by the time this runs.
import type { SupabaseClient } from "@supabase/supabase-js";
import { parse } from "tldts";
import { isMissingSchemaError } from "./dbErrors";
import { escapeHtml, sendEmail } from "./email";
import { channelsFor, type OwnerContext } from "./emergingThreatAlerts";
import { sendTeamsNotice } from "./msTeams";
import { ownerDomain } from "./scanners/registrableDomain";
import { sendSlackNotice } from "./slack";

const PAID_PLANS = new Set(["basic", "pro", "agency"]);
const DAY_MS = 24 * 60 * 60 * 1000;

/** How often a domain's full candidate set is re-checked. */
export const SWEEP_INTERVAL_DAYS = 7;
/** Bounds crt.sh queries per sweep. */
export const MAX_CANDIDATES = 60;
const CHECK_CONCURRENCY = 5;
/** Domains listed in one alert; the rest are counted. */
export const MAX_LISTED_CANDIDATES = 10;

// ---- Candidate generation (pure, offline) ----------------------------------

export type LookalikeCandidate = { domain: string; technique: string };

// A short, well-known table of visually/typographically confusable
// substitutions — not an attempt at full Unicode homoglyph coverage (IDN
// punycode lookalikes are a real but separate problem; this stays ASCII).
const CONFUSABLE_SUBSTITUTIONS: ReadonlyArray<readonly [string, string]> = [
  ["o", "0"],
  ["l", "1"],
  ["i", "1"],
  ["e", "3"],
  ["s", "5"],
  ["a", "4"],
  ["rn", "m"],
  ["m", "rn"],
  ["vv", "w"],
];

// Common, simple (single-label) TLDs swapped in for the original when it
// is one of these — ccTLDs and multi-part suffixes (co.uk, com.au) are left
// alone: swapping part of a multi-label suffix isn't the pattern phishing
// domains actually use, and generating every ccTLD would blow the cap.
const COMMON_TLDS = ["com", "net", "org", "co", "io", "info", "biz"];

function omissions(label: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < label.length; i++) out.push(label.slice(0, i) + label.slice(i + 1));
  return out;
}

function doublings(label: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < label.length; i++) out.push(label.slice(0, i + 1) + label[i] + label.slice(i + 1));
  return out;
}

function transpositions(label: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < label.length - 1; i++) {
    if (label[i] === label[i + 1]) continue; // swapping identical neighbours produces the same string
    out.push(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2));
  }
  return out;
}

function hyphenations(label: string): string[] {
  const out: string[] = [];
  for (let i = 1; i < label.length; i++) out.push(`${label.slice(0, i)}-${label.slice(i)}`);
  return out;
}

function substitutions(label: string): string[] {
  const out: string[] = [];
  for (const [from, to] of CONFUSABLE_SUBSTITUTIONS) {
    let idx = label.indexOf(from);
    while (idx !== -1) {
      out.push(label.slice(0, idx) + to + label.slice(idx + from.length));
      idx = label.indexOf(from, idx + 1);
    }
  }
  return out;
}

function tldSwaps(suffix: string): string[] {
  if (!COMMON_TLDS.includes(suffix)) return [];
  return COMMON_TLDS.filter((t) => t !== suffix);
}

/** The registrable label and public suffix of an already-resolved owner domain, or null if it can't be split (an IP, a bare suffix). */
function splitDomain(domain: string): { label: string; suffix: string } | null {
  const parsed = parse(domain, { allowPrivateDomains: true });
  if (!parsed.domainWithoutSuffix || !parsed.publicSuffix) return null;
  return { label: parsed.domainWithoutSuffix, suffix: parsed.publicSuffix };
}

/**
 * Pure, offline: a small, bounded set of domains one simple edit away from
 * `domain`. `domain` is expected to already be an owner domain (e.g. from
 * scanners/registrableDomain.ts's ownerDomain()) — this does not re-derive
 * it. Labels shorter than 4 characters are skipped (too few meaningful
 * single-edit variants to be worth checking). Never throws, makes no
 * network calls.
 */
export function generateLookalikeCandidates(domain: string): LookalikeCandidate[] {
  const split = splitDomain(domain);
  if (!split) return [];
  const { label, suffix } = split;
  if (label.length < 4) return [];

  const seen = new Set<string>([domain.toLowerCase()]);
  const candidates: LookalikeCandidate[] = [];
  const addLabels = (labels: string[], technique: string) => {
    for (const l of labels) {
      if (!l) continue;
      const candidateDomain = `${l}.${suffix}`;
      if (seen.has(candidateDomain)) continue;
      seen.add(candidateDomain);
      candidates.push({ domain: candidateDomain, technique });
    }
  };

  addLabels(omissions(label), "omission");
  addLabels(doublings(label), "doubling");
  addLabels(transpositions(label), "transposition");
  addLabels(hyphenations(label), "hyphenation");
  addLabels(substitutions(label), "substitution");
  for (const tld of tldSwaps(suffix)) {
    const candidateDomain = `${label}.${tld}`;
    if (seen.has(candidateDomain)) continue;
    seen.add(candidateDomain);
    candidates.push({ domain: candidateDomain, technique: "tld-swap" });
  }

  return candidates.slice(0, MAX_CANDIDATES);
}

// ---- crt.sh existence check -------------------------------------------------

const CRTSH_TIMEOUT_MS = 12_000;
/** crt.sh often answers 502/503 for a moment; one quick retry fixes most (same as recon.ts). */
const CRTSH_RETRY_DELAY_MS = 1_500;

async function fetchCrtSh(url: string): Promise<Response> {
  const attempt = () => fetch(url, { signal: AbortSignal.timeout(CRTSH_TIMEOUT_MS), headers: { Accept: "application/json" } });
  const res = await attempt();
  if (res.status < 500) return res;
  await new Promise((r) => setTimeout(r, CRTSH_RETRY_DELAY_MS));
  return attempt();
}

export type CandidateCheckResult = { status: "exists"; firstSeen: string | null } | { status: "not_found" } | { status: "error"; reason: string };

/**
 * Whether `domain` (an exact candidate, not a wildcard) has a real
 * certificate on record. The match is verified locally against each
 * returned name — never trusting crt.sh's own search behaviour alone —
 * since finding ANY cert naming this exact domain is strong evidence it is
 * registered and served, regardless of how crt.sh's server-side query
 * matched it.
 */
export async function checkCandidateDomain(domain: string): Promise<CandidateCheckResult> {
  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
    const res = await fetchCrtSh(url);
    if (!res.ok) return { status: "error", reason: `HTTP ${res.status}` };
    const body = (await res.json()) as Array<{ name_value: string; not_before?: string }>;
    let firstSeen: string | null = null;
    let found = false;
    for (const cert of body) {
      const names = cert.name_value.split(/\n/).map((n) => n.trim().toLowerCase());
      for (const name of names) {
        const display = name.startsWith("*.") ? name.slice(2) : name;
        if (display !== domain) continue;
        found = true;
        if (cert.not_before && (!firstSeen || cert.not_before < firstSeen)) firstSeen = cert.not_before;
      }
    }
    return found ? { status: "exists", firstSeen } : { status: "not_found" };
  } catch (err) {
    return { status: "error", reason: (err as Error).message };
  }
}

async function mapWithConcurrency<T, R>(items: T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

// ---- Message ----------------------------------------------------------------

export type LookalikeFinding = { domain: string; technique: string; firstSeen: string };

const TECHNIQUE_LABELS: Record<string, string> = {
  omission: "a character removed",
  doubling: "a character doubled",
  transposition: "two characters swapped",
  hyphenation: "a hyphen inserted",
  substitution: "a character swapped for a lookalike",
  "tld-swap": "a different top-level domain",
};

function formatDate(iso: string): string {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? new Date(t).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" }) : "an unknown date";
}

function findingLine(f: LookalikeFinding): string {
  return `${f.domain} (${TECHNIQUE_LABELS[f.technique] ?? f.technique}, first certificate ${formatDate(f.firstSeen)})`;
}

export function noticeTitle(domain: string, findings: LookalikeFinding[]): string {
  return `${findings.length} lookalike domain${findings.length === 1 ? "" : "s"} found for ${domain}`;
}

const WHY =
  "A domain this close to yours, with a real TLS certificate already issued for it, is a common setup for phishing or business-email-compromise against your customers or staff. It may be unrelated to you — but it's worth checking who registered it and what it serves.";

/** Plain lines for Slack/Teams (they escape them). */
export function noticeLines(domain: string, findings: LookalikeFinding[]): string[] {
  const listed = findings.slice(0, MAX_LISTED_CANDIDATES);
  const lines = [`Lookalike domain${listed.length === 1 ? "" : "s"} of ${domain}: ${listed.map(findingLine).join(", ")}`];
  const more = findings.length - listed.length;
  if (more > 0) lines.push(`…and ${more} more on the Assets page`);
  lines.push(WHY);
  return lines;
}

export function buildLookalikeDomainEmail(domain: string, findings: LookalikeFinding[], siteUrl: string): { subject: string; html: string } {
  const p = (text: string) => `<p style="margin:0 0 12px;font-size:14px;line-height:1.5;">${text}</p>`;
  const listed = findings.slice(0, MAX_LISTED_CANDIDATES);
  const more = findings.length - listed.length;
  const list = `<ul style="margin:0 0 12px;padding-left:20px;font-size:14px;line-height:1.5;">${listed.map((f) => `<li>${escapeHtml(findingLine(f))}</li>`).join("")}</ul>`;

  const html = `
    <div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:600px;margin:0 auto;color:#111827;">
      <h2 style="margin:0 0 8px;font-size:20px;">${escapeHtml(noticeTitle(domain, findings))}</h2>
      <p style="margin:0 0 8px;color:#4b5563;font-size:14px;line-height:1.5;">
        We checked domains that look one character different from ${escapeHtml(domain)} and found these already registered.
      </p>
      ${list}
      ${more > 0 ? p(`…and ${more} more, listed on the Assets page.`) : ""}
      ${p(escapeHtml(WHY))}
      <p style="margin:16px 0 0;font-size:13px;"><a href="${siteUrl}/dashboard/assets">Open Assets</a></p>
      <p style="margin:16px 0 0;color:#9ca3af;font-size:12px;">
        We tell you about each lookalike domain once. This only checks public certificate records — it never contacts
        the domain itself, and a false match is possible (an unrelated domain may happen to be one character away
        from yours). We re-check for new ones roughly every ${SWEEP_INTERVAL_DAYS} days.
      </p>
    </div>
  `;
  return { subject: noticeTitle(domain, findings), html };
}

// ---- The run ------------------------------------------------------------------

export type LookalikeMonitorResult = {
  /** Whether a full candidate sweep ran this call (false if not due yet, no alerting plan, or the domain couldn't be resolved). */
  swept: boolean;
  candidatesChecked: number;
  /** Newly found and claimed this run — what was (or would have been) alerted. */
  found: LookalikeFinding[];
  delivered: boolean;
  migrationPending: boolean;
  errors: string[];
};

export type LookalikeMonitorOptions = {
  now?: Date;
  siteUrl?: string;
  /** Overridable for tests; the default hits the real crt.sh. */
  checkCandidate?: (domain: string) => Promise<CandidateCheckResult>;
};

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
  const alerting = owner.isAdmin || (owner.status === "active" && PAID_PLANS.has(owner.plan ?? ""));
  return { owner, email: u?.email ?? null, alerting };
}

async function deliver(owner: OwnerContext, email: string | null, domain: string, findings: LookalikeFinding[], siteUrl: string): Promise<{ delivered: boolean; errors: string[] }> {
  const errors: string[] = [];
  let delivered = false;

  if (email) {
    const { subject, html } = buildLookalikeDomainEmail(domain, findings, siteUrl);
    const sent = await sendEmail({ to: email, subject, html });
    if (sent.ok) delivered = true;
    else errors.push(`email failed: ${sent.error}`);
  } else {
    errors.push("no email address on file");
  }

  const title = noticeTitle(domain, findings);
  const lines = noticeLines(domain, findings);
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

export async function sendLookalikeDomainAlerts(supabase: SupabaseClient, ownerId: string, targetUrl: string, opts: LookalikeMonitorOptions = {}): Promise<LookalikeMonitorResult> {
  const result: LookalikeMonitorResult = { swept: false, candidatesChecked: 0, found: [], delivered: false, migrationPending: false, errors: [] };
  const fail = (message: string) => {
    result.errors.push(message);
    console.error(`[lookalikeDomainMonitor] ${targetUrl}: ${message}`);
  };

  try {
    const nowDate = opts.now ?? new Date();
    const now = nowDate.toISOString();
    const siteUrl = opts.siteUrl ?? process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
    const host = new URL(targetUrl).hostname.toLowerCase();
    const domain = ownerDomain(host);
    if (!domain) return result; // an IP, localhost, or a bare public suffix — nothing to watch

    const { owner, email, alerting } = await loadOwner(supabase, ownerId);
    if (!alerting) return result; // a sweep costs real crt.sh queries; skip accounts that can never be alerted

    const sweep = await supabase.from("lookalike_domain_sweeps").select("swept_at").eq("owner", ownerId).eq("target_domain", domain).maybeSingle();
    if (sweep.error) {
      if (isMissingSchemaError(sweep.error)) {
        result.migrationPending = true;
        return result;
      }
      throw new Error(`could not load the sweep record: ${sweep.error.message}`);
    }
    const lastSweptAt = (sweep.data as { swept_at: string } | null)?.swept_at;
    if (lastSweptAt && nowDate.getTime() - Date.parse(lastSweptAt) < SWEEP_INTERVAL_DAYS * DAY_MS) return result; // not due yet

    const candidates = generateLookalikeCandidates(domain);
    if (candidates.length === 0) return result;

    const checkFn = opts.checkCandidate ?? checkCandidateDomain;
    const checked = await mapWithConcurrency(candidates, CHECK_CONCURRENCY, async (c) => [c, await checkFn(c.domain)] as const);
    result.candidatesChecked = checked.length;
    result.swept = true;

    // Record the sweep regardless of outcome, so a clean domain is still throttled correctly.
    const { error: sweepError } = await supabase.from("lookalike_domain_sweeps").upsert({ owner: ownerId, target_domain: domain, swept_at: now }, { onConflict: "owner,target_domain" });
    if (sweepError) fail(`could not record the sweep: ${sweepError.message}`);

    const existing = checked.filter(([, r]) => r.status === "exists") as Array<[LookalikeCandidate, { status: "exists"; firstSeen: string | null }]>;
    if (existing.length === 0) return result;

    // Insert any genuinely new rows. ignoreDuplicates means an already-known
    // candidate (reported or not) is left exactly as it was — never re-alerted.
    const rows = existing.map(([c, r]) => ({ owner: ownerId, target_domain: domain, candidate_domain: c.domain, technique: c.technique, first_seen_at: r.firstSeen ?? now }));
    const { error: insertError } = await supabase.from("lookalike_domains").upsert(rows, { onConflict: "owner,candidate_domain", ignoreDuplicates: true });
    if (insertError) {
      fail(`could not record lookalike domains: ${insertError.message}`);
      return result;
    }

    // Claim whichever of those rows are still pending — an already-known
    // one (ignoreDuplicates left it untouched above) was never inserted
    // fresh, so it stays notified and isn't reclaimed here.
    const candidateDomains = rows.map((r) => r.candidate_domain);
    const { data: claimed, error: claimError } = await supabase
      .from("lookalike_domains")
      .update({ notified_at: now })
      .eq("owner", ownerId)
      .eq("target_domain", domain)
      .is("notified_at", null)
      .in("candidate_domain", candidateDomains)
      .select("candidate_domain, technique, first_seen_at");
    if (claimError) {
      fail(`could not claim new lookalike domains: ${claimError.message}`);
      return result;
    }
    const found = (claimed ?? []) as Array<{ candidate_domain: string; technique: string; first_seen_at: string }>;
    if (found.length === 0) return result; // another sweep already claimed them

    result.found = found.map((f) => ({ domain: f.candidate_domain, technique: f.technique, firstSeen: f.first_seen_at }));

    const sent = await deliver(owner, email, domain, result.found, siteUrl);
    sent.errors.forEach(fail);
    if (sent.delivered) {
      result.delivered = true;
      return result;
    }

    // Nothing delivered: release the claim so the next sweep retries.
    const { error: releaseError } = await supabase.from("lookalike_domains").update({ notified_at: null }).eq("owner", ownerId).eq("notified_at", now).in("candidate_domain", candidateDomains);
    if (releaseError) fail(`could not release lookalike domains for a retry: ${releaseError.message}`);
    return result;
  } catch (err) {
    fail((err as Error).message);
    return result;
  }
}

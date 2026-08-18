// Subdomain discovery — passive attack-surface enumeration via Subfinder.
//
// WHY SUBFINDER AND NOT AMASS
// Subfinder is a single static Go binary, passive by default (it only queries
// third-party data sources — CT logs, passive DNS, threat-intel feeds — it
// never touches the customer's infrastructure), needs no API keys to be
// useful, and finishes a domain in seconds. Amass covers slightly more
// sources but v4 replaced the old "print hostnames to stdout" behaviour with
// an asset-database model (`amass enum` writes to a graph DB, results come
// back out via a separate `amass db` invocation), takes minutes rather than
// seconds, and is far heavier to install in an ephemeral CI runner. The extra
// coverage is not worth a multi-minute step and a second output format to
// parse, so Amass is deliberately NOT wired up here. If it is ever added it
// belongs behind an explicit opt-in option on runSubdomainDiscovery(), never
// on by default.
//
// PASSIVE ONLY. Subfinder's brute-force mode (-b / -w) and its active
// resolution mode (-active) are both deliberately not passed. This runs
// against customer domains on a schedule; generating brute-force DNS traffic
// at someone's nameservers is abusive and is not what was authorised. The
// only traffic this module originates towards the target's own DNS is a
// bounded set of ordinary A/CNAME lookups used to *evidence* the handful of
// findings that get escalated above info (see below).
//
// Follows the same contract as the other extended tools (src/worker/tools/*):
// a hard timeout, and { status: "not_configured" } rather than a throw when
// the binary is absent, so running outside the CI worker (Azure Functions,
// local dev, the synchronous dashboard scan path) degrades to "no findings"
// instead of failing the whole scan.
//
// NOTE ON OVERLAP WITH recon.ts: src/lib/scanners/recon.ts already emits a
// single "recon.subdomains-found" summary sourced from crt.sh alone. This
// module is a different, much wider source set and uses its own "subdomains.*"
// checkId namespace, so the two never collide in the findings diff. If the
// duplication ever reads as noise in a report, the crt.sh block in
// summariseResults() is the one to drop — not this.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Resolver } from "node:dns/promises";
import type { Finding } from "./index";
import { SUBDOMAINS_FOUND } from "./remediationText";

const execFileAsync = promisify(execFile);

// Our hard kill. SUBFINDER_MAX_TIME_MIN is subfinder's own internal budget and
// is set lower so the tool exits cleanly and we still get its partial results,
// rather than being SIGTERM'd with nothing on stdout.
const SUBFINDER_TIMEOUT_MS = 90_000;
const SUBFINDER_MAX_TIME_MIN = 1;

// A busy domain can return thousands of hostnames; stdout is small per line
// but bound it anyway rather than inheriting execFile's 1 MB default.
const SUBFINDER_MAX_BUFFER = 8 * 1024 * 1024;

// Caps. A domain with 400 subdomains must not produce a 400-row report:
// MAX_HOST_FINDINGS hosts get an individual info row and the rest are rolled
// into one summary finding.
const MAX_HOST_FINDINGS = 25;
// Ceiling on DNS lookups we perform for evidence-gathering.
const MAX_RESOLVE = 75;
// Ceiling on escalated (above-info) findings, so a badly broken domain still
// produces a readable report.
const MAX_RISK_FINDINGS = 15;
// Parallel DNS lookups.
const RESOLVE_CONCURRENCY = 8;
const RESOLVE_TIMEOUT_MS = 3_000;
// Wall-clock budget for the whole evidence-gathering phase.
const EVIDENCE_BUDGET_MS = 30_000;

/**
 * Hostname prefixes that are worth flagging *if* they resolve publicly.
 * Presence in DNS is not itself a vulnerability, so these only ever produce a
 * "low" — the finding says "this is publicly resolvable, confirm it is meant
 * to be", it does not claim the host is exploitable.
 */
const SENSITIVE_LABELS = [
  "admin", "dev", "development", "staging", "stage", "test", "testing", "uat",
  "qa", "sandbox", "internal", "intranet", "corp", "vpn", "jenkins", "gitlab",
  "grafana", "kibana", "jira", "confluence", "backup", "old", "legacy", "db",
  "database", "phpmyadmin", "portainer", "rancher",
];

/**
 * CNAME targets belonging to services that hand out hostnames first-come,
 * first-served. A CNAME pointing at one of these whose target no longer
 * resolves is the classic dangling-record subdomain takeover setup — and,
 * crucially, it is *evidenced*: we have the CNAME and we have the NXDOMAIN.
 * A CNAME at one of these services that DOES resolve is completely normal and
 * is never reported.
 */
const TAKEOVER_SERVICE_SUFFIXES: { suffix: string; service: string }[] = [
  { suffix: ".s3.amazonaws.com", service: "AWS S3" },
  { suffix: ".s3-website.amazonaws.com", service: "AWS S3 website" },
  { suffix: ".cloudfront.net", service: "AWS CloudFront" },
  { suffix: ".elasticbeanstalk.com", service: "AWS Elastic Beanstalk" },
  { suffix: ".azurewebsites.net", service: "Azure App Service" },
  { suffix: ".cloudapp.azure.com", service: "Azure Cloud Service" },
  { suffix: ".cloudapp.net", service: "Azure Cloud Service (classic)" },
  { suffix: ".trafficmanager.net", service: "Azure Traffic Manager" },
  { suffix: ".blob.core.windows.net", service: "Azure Blob Storage" },
  { suffix: ".github.io", service: "GitHub Pages" },
  { suffix: ".herokuapp.com", service: "Heroku" },
  { suffix: ".herokudns.com", service: "Heroku" },
  { suffix: ".netlify.app", service: "Netlify" },
  { suffix: ".ghost.io", service: "Ghost" },
  { suffix: ".wpengine.com", service: "WP Engine" },
  { suffix: ".pantheonsite.io", service: "Pantheon" },
  { suffix: ".surge.sh", service: "Surge" },
  { suffix: ".fastly.net", service: "Fastly" },
  { suffix: ".readthedocs.io", service: "Read the Docs" },
  { suffix: ".statuspage.io", service: "Statuspage" },
  { suffix: ".zendesk.com", service: "Zendesk" },
  { suffix: ".helpscoutdocs.com", service: "Help Scout" },
];

// ---- Types -----------------------------------------------------------------

export type SubdomainRecord = {
  host: string;
  /** null when we did not spend a lookup on this host (past MAX_RESOLVE). */
  resolves: boolean | null;
  /** First A/AAAA address, kept purely as evidence in the finding detail. */
  address: string | null;
  cname: string | null;
  /** Set only when cname points at a known service whose target is NXDOMAIN. */
  takeoverService: string | null;
  /** The SENSITIVE_LABELS entry this host's leftmost label matched, if any. */
  sensitiveLabel: string | null;
};

export type SubdomainsResult =
  | {
      status: "completed";
      domain: string;
      total: number;
      subdomains: SubdomainRecord[];
      findings: Finding[];
    }
  | { status: "not_configured"; subdomains: []; findings: [] }
  | { status: "error"; subdomains: []; findings: []; note: string };

// ---- Subfinder -------------------------------------------------------------

/**
 * Plain-line output (`-silent`) rather than JSON on purpose: subfinder's JSON
 * flag has moved between `-json` and `-oJ` across 2.x releases, and the only
 * extra field we would gain is which data source reported the host, which
 * nothing downstream uses. One hostname per line is stable across every
 * version we might end up with on a CI runner.
 */
async function runSubfinder(domain: string): Promise<string[] | "not_configured"> {
  let stdout = "";
  try {
    ({ stdout } = await execFileAsync(
      "subfinder",
      [
        "-d", domain,
        "-silent",              // hostnames only, no banner
        "-timeout", "10",       // per-source timeout, seconds
        "-max-time", String(SUBFINDER_MAX_TIME_MIN),
        "-nW",                  // drop wildcard-expansion noise
        // Deliberately absent: -b/-w (brute force), -active (resolves every
        // candidate against the target's nameservers). Passive only.
      ],
      { timeout: SUBFINDER_TIMEOUT_MS, maxBuffer: SUBFINDER_MAX_BUFFER }
    ));
  } catch (err) {
    const error = err as NodeJS.ErrnoException & { stdout?: string };
    // Binary absent — the "running outside the CI worker" case. Same contract
    // as src/worker/tools/*.ts: report it, never throw.
    if (error.code === "ENOENT") return "not_configured";
    // subfinder exits non-zero when an individual data source errors or when
    // -max-time cuts it short, but it has usually already printed the hosts it
    // did find. Keep those rather than throwing the whole run away.
    if (typeof error.stdout === "string" && error.stdout.trim().length > 0) {
      stdout = error.stdout;
    } else {
      throw err;
    }
  }

  const seen = new Set<string>();
  for (const raw of stdout.split("\n")) {
    const host = raw.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
    // Guard against a source echoing something outside the requested scope.
    if (!host || host === domain) continue;
    if (!host.endsWith(`.${domain}`)) continue;
    seen.add(host);
  }

  return [...seen].sort((a, b) => a.localeCompare(b));
}

// ---- Evidence gathering ----------------------------------------------------

function sensitiveLabelFor(host: string, domain: string): string | null {
  const prefix = host.slice(0, host.length - domain.length - 1);
  const labels = prefix.split(".");
  for (const label of labels) {
    if (SENSITIVE_LABELS.includes(label)) return label;
  }
  return null;
}

function takeoverServiceFor(cname: string): string | null {
  const target = cname.toLowerCase().replace(/\.$/, "");
  return TAKEOVER_SERVICE_SUFFIXES.find((s) => target.endsWith(s.suffix))?.service ?? null;
}

/**
 * One host's evidence pass: does it resolve, what does it CNAME to, and — only
 * when the CNAME points at a takeover-prone service — does that CNAME target
 * itself fail to resolve. That last lookup is what turns "this is a CNAME to
 * S3" (normal, unreportable) into "this is a CNAME to an S3 bucket that no
 * longer exists" (evidenced, reportable).
 */
async function gatherEvidence(host: string, domain: string, resolver: Resolver): Promise<SubdomainRecord> {
  const record: SubdomainRecord = {
    host,
    resolves: false,
    address: null,
    cname: null,
    takeoverService: null,
    sensitiveLabel: sensitiveLabelFor(host, domain),
  };

  const [v4, cname] = await Promise.all([
    resolver.resolve4(host).catch(() => [] as string[]),
    resolver.resolveCname(host).catch(() => [] as string[]),
  ]);

  if (v4.length > 0) {
    record.resolves = true;
    record.address = v4[0];
  } else {
    const v6 = await resolver.resolve6(host).catch(() => [] as string[]);
    if (v6.length > 0) {
      record.resolves = true;
      record.address = v6[0];
    }
  }

  if (cname.length > 0) {
    record.cname = cname[0].toLowerCase().replace(/\.$/, "");
    const service = takeoverServiceFor(record.cname);
    if (service) {
      // A CNAME whose own target is gone is the dangling record. If the host
      // still resolves through it, the resource is live and there is nothing
      // to report.
      const targetV4 = await resolver.resolve4(record.cname).catch(() => [] as string[]);
      if (targetV4.length === 0 && !record.resolves) {
        record.takeoverService = service;
      }
    }
  }

  return record;
}

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  deadline: number,
  fn: (item: T) => Promise<R>
): Promise<R[]> {
  const results: R[] = [];
  let index = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (index < items.length && Date.now() < deadline) {
      const i = index++;
      results.push(await fn(items[i]));
    }
  });
  await Promise.all(workers);
  return results;
}

// ---- Finding construction --------------------------------------------------

const TAKEOVER_FIX = `Remove or repoint the DNS record immediately, then confirm nobody has already
claimed the target name.

A CNAME pointing at a deprovisioned cloud resource lets anyone who registers
that name on the same provider serve content from your hostname — which means
valid TLS, your domain in the address bar, and any cookies scoped to the parent
domain. Delete the record if the service is retired, or recreate the resource
if the subdomain is still needed.`;

const SENSITIVE_HOST_FIX = `Confirm this host is meant to be reachable from the public internet.

Non-production and administrative hosts are routinely deployed with default
credentials, debug output, or copies of production data. If it must stay
online, put it behind VPN, IP allow-listing, or SSO rather than relying on the
hostname being hard to guess — it is not, as this scan demonstrates.`;

/**
 * checkId is "<module>.<check-name>[:<key>]" with the hostname as the key, so
 * findingsDiff.ts matches on the hostname itself. That gives a genuinely
 * useful property for free: a subdomain that appears between two scans shows
 * up as a NEW finding, and one that is decommissioned shows up as FIXED. That
 * is the whole point of running this on a schedule — the report is a live
 * attack-surface inventory, not just a one-off list. It also means the per-host
 * rows must be emitted deterministically, which is why the host list is sorted
 * before the MAX_HOST_FINDINGS cap is applied: an unstable cap would make
 * arbitrary hosts flap between NEW and FIXED on every run.
 */
function buildFindings(domain: string, records: SubdomainRecord[]): Finding[] {
  const findings: Finding[] = [];

  // --- Escalated: evidenced dangling CNAME (high) ---------------------------
  const takeovers = records.filter((r) => r.takeoverService !== null).slice(0, MAX_RISK_FINDINGS);
  for (const r of takeovers) {
    findings.push({
      checkId: `subdomains.takeover-candidate:${r.host}`,
      severity: "high",
      title: `Possible subdomain takeover: ${r.host}`,
      detail: `${r.host} is a CNAME to ${r.cname} (${r.takeoverService}), but that target does not resolve. A dangling CNAME to a deprovisioned ${r.takeoverService} resource can usually be claimed by anyone, letting them serve content from your hostname. Verify before acting — the resource may simply be mid-deploy.`,
      remediation: TAKEOVER_FIX,
    });
  }

  // --- Escalated: sensitive hostname that actually resolves (low) -----------
  // Only hosts we confirmed resolve. A name that merely appeared in a passive
  // data source is not evidence that anything is reachable today.
  const sensitive = records
    .filter((r) => r.sensitiveLabel !== null && r.resolves === true && r.takeoverService === null)
    .slice(0, MAX_RISK_FINDINGS);
  for (const r of sensitive) {
    findings.push({
      checkId: `subdomains.sensitive-host:${r.host}`,
      severity: "low",
      title: `Non-production host publicly resolvable: ${r.host}`,
      detail: `${r.host} resolves publicly to ${r.address}. The "${r.sensitiveLabel}" label suggests a non-production or administrative host. This is not a vulnerability on its own — it is flagged so you can confirm the exposure is intentional and that the host is authenticated.`,
      remediation: SENSITIVE_HOST_FIX,
    });
  }

  // --- Inventory: everything else is info ------------------------------------
  if (records.length === 0) return findings;

  const listed = records.slice(0, MAX_HOST_FINDINGS);
  for (const r of listed) {
    const resolution =
      r.resolves === true
        ? `resolves to ${r.address}`
        : r.resolves === false
          ? "does not currently resolve"
          : "not resolved (lookup budget reached)";
    findings.push({
      checkId: `subdomains.discovered:${r.host}`,
      severity: "info",
      title: `Subdomain: ${r.host}`,
      detail: `Discovered by passive enumeration (Subfinder); ${resolution}${r.cname ? `; CNAME to ${r.cname}` : ""}. Asset inventory only — no vulnerability is implied.`,
      remediation: SUBDOMAINS_FOUND,
    });
  }

  const remaining = records.length - listed.length;
  if (remaining > 0) {
    findings.push({
      checkId: "subdomains.discovered-additional",
      severity: "info",
      title: `${remaining} further subdomain(s) of ${domain} not listed individually`,
      detail: `Passive enumeration found ${records.length} subdomains in total; the first ${MAX_HOST_FINDINGS} are listed above. Additional: ${records.slice(MAX_HOST_FINDINGS, MAX_HOST_FINDINGS + 10).map((r) => r.host).join(", ")}${remaining > 10 ? ` (+${remaining - 10} more)` : ""}.`,
      remediation: SUBDOMAINS_FOUND,
    });
  }

  return findings;
}

// ---- Main ------------------------------------------------------------------

/**
 * Passive subdomain discovery for the target's hostname.
 *
 * Scope note: the domain enumerated is the target's own hostname with a
 * leading "www." stripped — the same rule src/lib/scanners/recon.ts uses.
 * Walking up to the registrable apex would enumerate infrastructure the
 * customer never submitted (and may not own), which is out of scope for an
 * authorised scan of a single target.
 */
export async function runSubdomainDiscovery(targetUrl: string): Promise<SubdomainsResult> {
  let domain: string;
  try {
    domain = new URL(targetUrl).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return { status: "error", subdomains: [], findings: [], note: "Invalid URL" };
  }

  let hosts: string[] | "not_configured";
  try {
    hosts = await runSubfinder(domain);
  } catch (err) {
    return {
      status: "error",
      subdomains: [],
      findings: [],
      note: `subfinder exited: ${(err as Error).message}`,
    };
  }

  if (hosts === "not_configured") {
    return { status: "not_configured", subdomains: [], findings: [] };
  }

  // Evidence pass over a bounded prefix of the (sorted, so deterministic)
  // host list. Hosts past the budget still appear in the inventory, just with
  // resolves: null — we say "not checked", never guess.
  const resolver = new Resolver({ timeout: RESOLVE_TIMEOUT_MS, tries: 1 });
  const toResolve = hosts.slice(0, MAX_RESOLVE);
  const deadline = Date.now() + EVIDENCE_BUDGET_MS;

  const resolved = await mapWithConcurrency(toResolve, RESOLVE_CONCURRENCY, deadline, (host) =>
    gatherEvidence(host, domain, resolver).catch(
      (): SubdomainRecord => ({
        host,
        resolves: null,
        address: null,
        cname: null,
        takeoverService: null,
        sensitiveLabel: sensitiveLabelFor(host, domain),
      })
    )
  );

  const resolvedHosts = new Set(resolved.map((r) => r.host));
  const unresolved: SubdomainRecord[] = hosts
    .filter((h) => !resolvedHosts.has(h))
    .map((host) => ({
      host,
      resolves: null,
      address: null,
      cname: null,
      takeoverService: null,
      sensitiveLabel: sensitiveLabelFor(host, domain),
    }));

  const subdomains = [...resolved, ...unresolved].sort((a, b) => a.host.localeCompare(b.host));

  return {
    status: "completed",
    domain,
    total: subdomains.length,
    subdomains,
    findings: buildFindings(domain, subdomains),
  };
}

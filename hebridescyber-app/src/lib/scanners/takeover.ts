// Dangling DNS / subdomain takeover detection.
//
// A subdomain whose CNAME still points at a cloud resource that has been
// deleted (an Azure web app, an S3 bucket, a GitHub Pages site) can often be
// claimed by anyone who creates a resource with the same name — and then
// serves their content, phishing pages or cookie-stealing scripts from the
// customer's own domain. The NCSC's EASM buyer's guide lists it under DNS
// security. Detection only: this never tries to claim anything.
//
// Evidence discipline (docs/SCANNER-CONVENTIONS.md §4): a finding needs BOTH
// (1) a CNAME to a provider in TAKEOVER_PROVIDERS and (2) that provider's own
// proof the resource is gone — NXDOMAIN for the CNAME target (Azure, Elastic
// Beanstalk: the name is free to register), or the provider's unclaimed-
// resource page in the response body. A timeout, SERVFAIL or unfamiliar page
// is not evidence and reports nothing.
//
// Candidates are the site's own host plus the subdomains recon.ts found in
// Certificate Transparency logs, scoped to the site's registrable domain.
import { resolve4, resolveCname } from "node:dns/promises";
import { isWithinDomain, ownerDomain } from "./registrableDomain";

export type TakeoverEvidence = { kind: "nxdomain" } | { kind: "body"; marker: string };

export type TakeoverProvider = {
  name: string;
  cname: RegExp;
  evidence: TakeoverEvidence;
  /** "high": re-registering the name is documented as open to anyone.
   *  "medium": the record is certainly dangling, but whether someone else
   *  can claim it depends on the provider's current verification rules. */
  confidence: "high" | "medium";
};

const NX: TakeoverEvidence = { kind: "nxdomain" };

// Fingerprints are the providers' own "no such resource" responses, as
// catalogued by the security community (e.g. EdOverflow's can-i-take-over-xyz).
// Keep this list conservative: an entry here turns a page into a finding.
export const TAKEOVER_PROVIDERS: TakeoverProvider[] = [
  { name: "Azure App Service", cname: /\.azurewebsites\.net$/i, evidence: NX, confidence: "high" },
  { name: "Azure Cloud Services", cname: /\.cloudapp\.(?:net|azure\.com)$/i, evidence: NX, confidence: "high" },
  { name: "Azure Traffic Manager", cname: /\.trafficmanager\.net$/i, evidence: NX, confidence: "high" },
  { name: "Azure Blob Storage", cname: /\.blob\.core\.windows\.net$/i, evidence: NX, confidence: "high" },
  { name: "Azure CDN", cname: /\.azureedge\.net$/i, evidence: NX, confidence: "high" },
  { name: "AWS Elastic Beanstalk", cname: /\.elasticbeanstalk\.com$/i, evidence: NX, confidence: "high" },
  { name: "Amazon S3", cname: /\.s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com$/i, evidence: { kind: "body", marker: "NoSuchBucket" }, confidence: "high" },
  { name: "GitHub Pages", cname: /\.github\.io$/i, evidence: { kind: "body", marker: "There isn't a GitHub Pages site here." }, confidence: "high" },
  { name: "Bitbucket", cname: /\.bitbucket\.io$/i, evidence: { kind: "body", marker: "Repository not found" }, confidence: "high" },
  { name: "Pantheon", cname: /\.pantheonsite\.io$/i, evidence: { kind: "body", marker: "The gods are wise, but do not know of the site which you seek." }, confidence: "high" },
  { name: "Surge.sh", cname: /\.surge\.sh$/i, evidence: { kind: "body", marker: "project not found" }, confidence: "high" },
  { name: "Heroku", cname: /\.(?:herokuapp|herokudns)\.com$/i, evidence: { kind: "body", marker: "no-such-app" }, confidence: "medium" },
  { name: "Shopify", cname: /\.myshopify\.com$/i, evidence: { kind: "body", marker: "Sorry, this shop is currently unavailable." }, confidence: "medium" },
  { name: "Fastly", cname: /\.fastly\.net$/i, evidence: { kind: "body", marker: "Fastly error: unknown domain" }, confidence: "medium" },
  { name: "Tumblr", cname: /^domains\.tumblr\.com$/i, evidence: { kind: "body", marker: "Whatever you were looking for doesn't currently exist at this address." }, confidence: "medium" },
];

export type DanglingRecord = {
  host: string;
  cname: string;
  provider: string;
  confidence: "high" | "medium";
  /** Human-readable proof, shown in the finding. */
  evidence: string;
};

export type TakeoverResult =
  | { status: "checked"; hostsChecked: number; dangling: DanglingRecord[] }
  | { status: "not_applicable"; note: string }
  | { status: "error"; note: string };

export const MAX_HOSTS = 60;
const CONCURRENCY = 8;
const HTTP_TIMEOUT_MS = 6_000;
const DNS_TIMEOUT_MS = 5_000;
const BODY_LIMIT = 64 * 1024;

export function matchProvider(cname: string): TakeoverProvider | null {
  const target = cname.toLowerCase().replace(/\.$/, "");
  return TAKEOVER_PROVIDERS.find((p) => p.cname.test(target)) ?? null;
}

/** The hosts worth checking: the site itself plus CT-log subdomains inside
 *  its owner's domain (never a hosting platform's shared one), wildcards
 *  dropped, de-duplicated, capped. */
export function candidateHosts(targetHost: string, subdomains: string[]): string[] {
  const domain = ownerDomain(targetHost);
  if (!domain) return [];
  const hosts = new Set<string>([targetHost.toLowerCase()]);
  for (const raw of subdomains) {
    for (const name of raw.split(/\s+/)) {
      const host = name.trim().toLowerCase().replace(/\.$/, "");
      if (!host || host.includes("*") || !isWithinDomain(host, domain)) continue;
      hosts.add(host);
    }
  }
  return [...hosts].sort().slice(0, MAX_HOSTS);
}

/** node:dns/promises lookups take no AbortSignal, so bound them here. The
 *  timer is cleared once the lookup settles, so the losing side never
 *  becomes an unhandled rejection. */
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error("DNS lookup timed out"), { code: "ETIMEOUT" })), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** True only on a definitive NXDOMAIN — every other failure is "unknown". */
async function isNxdomain(name: string): Promise<boolean> {
  try {
    await withTimeout(resolve4(name), DNS_TIMEOUT_MS);
    return false;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "ENOTFOUND";
  }
}

async function bodyContains(host: string, marker: string): Promise<boolean> {
  // http first: an unclaimed resource usually has no certificate for the
  // customer's hostname, so https fails before the provider's page loads.
  for (const scheme of ["http", "https"]) {
    try {
      const res = await fetch(`${scheme}://${host}/`, { redirect: "manual", signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
      const body = (await res.text()).slice(0, BODY_LIMIT);
      if (body.includes(marker)) return true;
    } catch {
      // try the next scheme
    }
  }
  return false;
}

export async function checkHost(host: string): Promise<DanglingRecord | null> {
  let cnames: string[];
  try {
    cnames = await withTimeout(resolveCname(host), DNS_TIMEOUT_MS);
  } catch {
    return null; // no CNAME (or unresolvable) — nothing dangling to point at
  }
  for (const cname of cnames) {
    const provider = matchProvider(cname);
    if (!provider) continue;
    const target = cname.toLowerCase().replace(/\.$/, "");
    if (provider.evidence.kind === "nxdomain") {
      if (await isNxdomain(target)) {
        return { host, cname: target, provider: provider.name, confidence: provider.confidence, evidence: `${target} does not exist (NXDOMAIN)` };
      }
    } else if (await bodyContains(host, provider.evidence.marker)) {
      return {
        host, cname: target, provider: provider.name, confidence: provider.confidence,
        evidence: `${host} returns ${provider.name}'s "${provider.evidence.marker}" page`,
      };
    }
  }
  return null;
}

export async function checkTakeover(targetUrl: string, subdomains: string[]): Promise<TakeoverResult> {
  let targetHost: string;
  try {
    targetHost = new URL(targetUrl).hostname;
  } catch {
    return { status: "error", note: "Invalid target URL" };
  }
  const hosts = candidateHosts(targetHost, subdomains);
  if (hosts.length === 0) return { status: "not_applicable", note: "No registrable domain to check (e.g. a bare IP address)." };

  const dangling: DanglingRecord[] = [];
  for (let i = 0; i < hosts.length; i += CONCURRENCY) {
    const batch = await Promise.all(hosts.slice(i, i + CONCURRENCY).map((h) => checkHost(h).catch(() => null)));
    for (const record of batch) if (record) dangling.push(record);
  }
  return { status: "checked", hostsChecked: hosts.length, dangling };
}

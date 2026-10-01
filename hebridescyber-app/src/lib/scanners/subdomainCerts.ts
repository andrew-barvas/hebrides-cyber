// Certificate expiry across the site's other hostnames.
//
// tls.ts checks the certificate on the address scanned. A lapsed certificate
// on shop., api. or portal. breaks those just as completely, and nobody is
// looking at them. Hostnames come from recon.ts's Certificate Transparency
// results; the ones issued a certificate most recently are checked first,
// since a host still being issued certificates is most likely in use.
//
// Evidence: a finding needs a completed handshake and a certificate read
// from it (tls.ts's readCertificate, which also reads expired ones). A host
// that doesn't answer on 443 is no evidence either way — CT logs list plenty
// of hostnames that no longer exist.
//
// Certificates are grouped: a wildcard served on ten hosts is one renewal,
// so one finding, keyed by the certificate's name (stable across renewals).
// The scanned site's own certificate is skipped — tls.ts reports that one.
import { isWithinDomain, registrableDomain } from "./registrableDomain";
import { readCertificate, type CertificateRead } from "./tls";
import type { SubdomainEntry } from "./recon";

export const MAX_SUBDOMAIN_CERT_HOSTS = 20;
const CONCURRENCY = 8;
/** Same window as the main site's tls.cert-expiring. */
export const SUBDOMAIN_CERT_WARN_DAYS = 21;

export type SubdomainCertIssue = {
  state: "expired" | "expiring";
  /** The certificate's subject name, e.g. "*.example.com". */
  certName: string;
  hosts: string[];
  validTo: string;
  daysUntilExpiry: number;
  issuer: string;
};

export type SubdomainCertsResult =
  | { status: "checked"; hostsChecked: number; hostsAnswering: number; issues: SubdomainCertIssue[] }
  | { status: "not_applicable"; note: string }
  | { status: "error"; note: string };

/** Subdomains to check: within the site's registered domain, not the site
 *  itself, no wildcards, most recently certified first. */
export function pickHosts(targetHost: string, entries: SubdomainEntry[], max = MAX_SUBDOMAIN_CERT_HOSTS): string[] {
  const domain = registrableDomain(targetHost);
  if (!domain) return [];
  const self = targetHost.toLowerCase();
  const latest = new Map<string, number>();
  for (const entry of entries) {
    for (const raw of entry.name.split(/\s+/)) {
      const host = raw.trim().toLowerCase().replace(/\.$/, "");
      if (!host || host === self || host.includes("*") || !isWithinDomain(host, domain)) continue;
      const issued = Date.parse(entry.notBefore);
      latest.set(host, Math.max(latest.get(host) ?? 0, Number.isNaN(issued) ? 0 : issued));
    }
  }
  return [...latest.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, max)
    .map(([host]) => host);
}

/** One issue per certificate, from the certificates that were read. */
export function groupCertIssues(certs: CertificateRead[], skipFingerprint?: string | null): SubdomainCertIssue[] {
  const byCert = new Map<string, { cert: CertificateRead; hosts: string[] }>();
  for (const cert of certs) {
    if (cert.daysUntilExpiry === null || !cert.validTo) continue;
    if (skipFingerprint && cert.fingerprint === skipFingerprint) continue;
    const expired = cert.trustProblem === "expired" || cert.daysUntilExpiry < 0;
    if (!expired && cert.daysUntilExpiry >= SUBDOMAIN_CERT_WARN_DAYS) continue;
    const key = cert.fingerprint ?? `${cert.subject}|${cert.validTo}`;
    const group = byCert.get(key);
    if (group) group.hosts.push(cert.host);
    else byCert.set(key, { cert, hosts: [cert.host] });
  }
  return [...byCert.values()].map(({ cert, hosts }) => ({
    state: cert.trustProblem === "expired" || cert.daysUntilExpiry! < 0 ? "expired" : "expiring",
    certName: cert.subject,
    hosts: hosts.sort(),
    validTo: cert.validTo!,
    daysUntilExpiry: cert.daysUntilExpiry!,
    issuer: cert.issuer,
  }));
}

export async function checkSubdomainCerts(
  targetUrl: string,
  subdomains: SubdomainEntry[],
  mainCertFingerprint?: string | null
): Promise<SubdomainCertsResult> {
  let targetHost: string;
  try {
    targetHost = new URL(targetUrl).hostname;
  } catch {
    return { status: "error", note: `Invalid target URL: ${targetUrl}` };
  }

  const hosts = pickHosts(targetHost, subdomains);
  if (hosts.length === 0) return { status: "not_applicable", note: "No other hostnames on this domain were found in Certificate Transparency logs." };

  const certs: CertificateRead[] = [];
  for (let i = 0; i < hosts.length; i += CONCURRENCY) {
    const batch = await Promise.all(hosts.slice(i, i + CONCURRENCY).map((h) => readCertificate(h).catch(() => null)));
    for (const cert of batch) if (cert) certs.push(cert);
  }

  // Nothing answered at all: no evidence about any of them, including the
  // ones flagged last time — so not "checked".
  if (certs.length === 0) return { status: "error", note: `None of the ${hosts.length} subdomains checked answered on port 443.` };

  return { status: "checked", hostsChecked: hosts.length, hostsAnswering: certs.length, issues: groupCertIssues(certs, mainCertFingerprint) };
}

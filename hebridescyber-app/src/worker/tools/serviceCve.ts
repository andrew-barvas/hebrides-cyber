// Known-CVE matching for the services networkExposure.ts identifies (P1-3):
// "port 22 open" becomes "OpenSSH 7.4 on port 22, 3 CVEs, end of life".
//
// For each open port nmap -sV identified, the service's CPE (nmap's <cpe>
// element, e.g. cpe:/a:openbsd:openssh:7.4) and version are looked up in the
// local CPE -> CVE index (src/lib/cveIndex.ts, built nightly from NVD), and
// the product is checked against endoflife.date (endOfLife.ts). Banner
// reading only: nothing here sends a request to the target. KEV and EPSS
// context is added by threatIntel.ts's final pass, which reads each
// finding's cveIds, the same as for every other CVE-backed finding.
//
// EVIDENCE RULES (docs/SCANNER-CONVENTIONS.md)
//   - A CVE is reported only when the version is inside a version-bounded
//     NVD criterion for that CPE, and the finding cites the criterion. A
//     criterion NVD lists only in combination with something else (an app on
//     a particular OS or appliance) is not reported.
//   - No version (nmap named the product but not its version) is reported as
//     "version unknown", never as a CVE.
//   - A distribution-packaged service (Ubuntu's "8.9p1 Ubuntu 3ubuntu0.10")
//     may have the fix backported under the same upstream number, so its CVE
//     findings are "info" and say so.
//   - Every case where we could not look — the index unavailable or stale, no
//     CPE, an unorderable version, a range the version can't be placed in, a
//     failed endoflife.date read — goes into `incompleteChecks`, the checkId
//     prefixes findingLifecycle.ts must not resolve this scan. Silence there
//     is "didn't look", never "fixed" (CLAUDE.md rule 7).
import type { Finding } from "../../lib/scanners";
import type { NmapPort } from "./nmap";
import { parseCpe, type CveIndex, type CveMatch } from "../../lib/cveIndex";
import { evaluateVersion, eolSeverity, fetchEolProduct, type EolEntry, type EolVerdict } from "../../lib/scanners/endOfLife";
import { endOfLifeRemediation, serviceCveRemediation } from "../../lib/scanners/remediationText";

export const SERVICE_CVE_CHECK = "network-exposure.service-cve";
export const SERVICE_EOL_CHECK = "network-exposure.service-eol";
export const SERVICE_VERSION_UNKNOWN_CHECK = "network-exposure.service-version-unknown";

export type ServiceCveState =
  /** Looked up: `matches` is the answer (possibly empty). */
  | "checked"
  /** nmap named a product but no version. */
  | "version_unknown"
  /** nmap matched no application CPE, so there is nothing to look up. */
  | "no_cpe"
  /** A version scheme the index can't order. */
  | "unordered_version"
  /** The index lookup failed. */
  | "error";

export type ServiceEol =
  | { state: "checked"; product: string; label: string; verdict: EolVerdict | null }
  | { state: "not_tracked" }
  | { state: "version_unknown" }
  | { state: "error"; note: string };

export type ServiceCveService = {
  port: number;
  protocol: string;
  service: string;
  product: string | null;
  /** The version compared: the CPE's own, else the first word of nmap's version. */
  version: string | null;
  /** nmap's application CPE as emitted. */
  cpe: string | null;
  /** Distribution named in the banner, which may backport fixes. */
  packagedBy: string | null;
  state: ServiceCveState;
  note?: string;
  /** Unconditional matches only; conditional ones are not evidence here. */
  matches: CveMatch[];
  undetermined: string[];
  eol: ServiceEol;
};

export type ServiceCveResult =
  | { status: "checked"; services: ServiceCveService[]; indexedThrough: string | null }
  | { status: "not_configured"; note: string; services: ServiceCveService[] }
  | { status: "error"; note: string; services: ServiceCveService[] };

// ---- Distribution packaging ---------------------------------------------------------

const DISTROS: Array<[RegExp, string]> = [
  [/\bubuntu\b/i, "Ubuntu"],
  [/\bdebian\b|\bdeb\d+u\d+\b/i, "Debian"],
  [/\bred ?hat\b|\brhel\b|\.el\d+\b/i, "Red Hat"],
  [/\bcentos\b/i, "CentOS"],
  [/\bfedora\b/i, "Fedora"],
  [/\bsuse\b/i, "SUSE"],
  [/\bamazon linux\b|\bamzn\d*\b/i, "Amazon Linux"],
  [/\braspbian\b/i, "Raspbian"],
];

const DISTRO_OS_CPES: Record<string, string> = {
  "canonical:ubuntu_linux": "Ubuntu",
  "debian:debian_linux": "Debian",
  "redhat:enterprise_linux": "Red Hat",
};

/** The distribution a banner names, if any (nmap's version, extrainfo or OS CPE). */
export function packagedByFrom(port: Pick<NmapPort, "productVersion" | "extraInfo" | "cpes">): string | null {
  const text = [port.productVersion ?? "", port.extraInfo ?? ""].join(" ");
  for (const [re, name] of DISTROS) if (re.test(text)) return name;
  for (const raw of port.cpes ?? []) {
    const cpe = parseCpe(raw);
    if (cpe?.part === "o") {
      const name = DISTRO_OS_CPES[`${cpe.vendor}:${cpe.product}`];
      if (name) return name;
    }
  }
  return null;
}

// ---- End of life ------------------------------------------------------------------------

/**
 * Application CPE (as nmap or NVD names it) → endoflife.date product. Every
 * slug was checked against https://endoflife.date/api/<slug>.json (nginx and
 * apache-http-server are endOfLife.ts's own; postgresql, mysql, redis,
 * mongodb and elasticsearch checked 2026-11-01). OpenSSH has no product there.
 */
export const SERVICE_EOL_PRODUCTS: Record<string, { product: string; label: string }> = {
  "f5:nginx": { product: "nginx", label: "nginx" },
  "igor_sysoev:nginx": { product: "nginx", label: "nginx" },
  "nginx:nginx": { product: "nginx", label: "nginx" },
  "apache:http_server": { product: "apache-http-server", label: "Apache HTTP Server" },
  "oracle:mysql": { product: "mysql", label: "MySQL" },
  "mysql:mysql": { product: "mysql", label: "MySQL" },
  "postgresql:postgresql": { product: "postgresql", label: "PostgreSQL" },
  "redis:redis": { product: "redis", label: "Redis" },
  "redislabs:redis": { product: "redis", label: "Redis" },
  "mongodb:mongodb": { product: "mongodb", label: "MongoDB" },
  "elastic:elasticsearch": { product: "elasticsearch", label: "Elasticsearch" },
  "elasticsearch:elasticsearch": { product: "elasticsearch", label: "Elasticsearch" },
};

// ---- Matching -------------------------------------------------------------------------------

export type ServiceCveOptions = {
  now?: Date;
  /** endoflife.date reader; endOfLife.ts's cached fetch by default. */
  fetchEol?: (product: string) => Promise<EolEntry[] | null>;
};

function versionFor(port: NmapPort, cpeVersion: string | null): string | null {
  if (cpeVersion) return cpeVersion;
  const first = port.productVersion?.trim().split(/\s+/)[0];
  return first ? first.toLowerCase() : null;
}

/**
 * Looks every identified service up. `index` null means the caller had no
 * index to give (no database client): that is "not_configured", and like an
 * index error it leaves every service-cve finding unresolved this scan.
 */
export async function matchServiceCves(ports: NmapPort[], index: CveIndex | null, options: ServiceCveOptions = {}): Promise<ServiceCveResult> {
  const now = options.now ?? new Date();
  const fetchEol = options.fetchEol ?? fetchEolProduct;
  const eolData = new Map<string, Promise<EolEntry[] | null>>();
  let indexError: string | null = null;
  let indexedThrough: string | null = null;

  const services = await Promise.all(
    ports.map(async (port): Promise<ServiceCveService> => {
      const appCpe = (port.cpes ?? []).find((c) => parseCpe(c)?.part === "a") ?? null;
      const name = appCpe ? parseCpe(appCpe) : null;
      const version = versionFor(port, name?.version ?? null);
      const base = {
        port: port.port,
        protocol: port.protocol,
        service: port.service,
        product: port.product ?? null,
        version,
        cpe: appCpe,
        packagedBy: packagedByFrom(port),
        matches: [] as CveMatch[],
        undetermined: [] as string[],
      };

      // End of life, independent of the CVE index.
      let eol: ServiceEol = { state: "not_tracked" };
      const eolProduct = name ? SERVICE_EOL_PRODUCTS[`${name.vendor}:${name.product}`] : undefined;
      if (eolProduct) {
        if (!version) eol = { state: "version_unknown" };
        else {
          let p = eolData.get(eolProduct.product);
          if (!p) {
            p = fetchEol(eolProduct.product);
            eolData.set(eolProduct.product, p);
          }
          const entries = await p;
          eol = entries
            ? { state: "checked", product: eolProduct.product, label: eolProduct.label, verdict: evaluateVersion(entries, version, now) }
            : { state: "error", note: `endoflife.date lookup failed for ${eolProduct.product}` };
        }
      }

      if (!name) {
        if (port.product && !port.productVersion) return { ...base, state: "version_unknown", eol };
        return { ...base, state: "no_cpe", eol };
      }
      if (!index) return { ...base, state: "error", note: "No CVE index available", eol };

      const result = await index.lookup({ cpe: appCpe!, version });
      switch (result.status) {
        case "version_unknown":
          return { ...base, state: "version_unknown", eol };
        case "unordered_version":
          return { ...base, state: "unordered_version", eol };
        case "error":
          indexError ??= result.note;
          return { ...base, state: "error", note: result.note, eol };
        case "checked":
          indexedThrough = result.indexedThrough;
          return {
            ...base,
            state: "checked",
            matches: result.matches.filter((m) => !m.conditional),
            undetermined: result.undetermined,
            eol,
          };
      }
    })
  );

  if (!index) return { status: "not_configured", note: "No CVE index available to this scan.", services };
  if (indexError) return { status: "error", note: indexError, services };
  return { status: "checked", services, indexedThrough };
}

/**
 * The checkId prefixes this scan could not evaluate (see the header). A
 * finding whose checkId equals one, or extends it with ":…", must not be
 * resolved by its absence.
 */
export function incompleteServiceChecks(result: ServiceCveResult): string[] {
  const out: string[] = [];
  if (result.status !== "checked") out.push(SERVICE_CVE_CHECK);
  for (const s of result.services) {
    if (result.status === "checked" && s.state !== "checked") out.push(`${SERVICE_CVE_CHECK}:${s.port}`);
    for (const cve of s.undetermined) out.push(`${SERVICE_CVE_CHECK}:${s.port}:${cve}`);
    if (s.eol.state === "error" || s.eol.state === "version_unknown") out.push(`${SERVICE_EOL_CHECK}:${s.port}`);
  }
  return out;
}

// ---- Findings -----------------------------------------------------------------------------------

/** CVSS → severity; an unscored CVE is "medium", as in softwareCveDb.ts. */
export function severityForCvss(score: number | null): Finding["severity"] {
  if (score === null) return "medium";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function labelOf(s: ServiceCveService): string {
  return s.product ?? s.service;
}

function eolSentence(eol: ServiceEol): string {
  if (eol.state !== "checked" || !eol.verdict) return "";
  if (eol.verdict.state === "unsupported") return ` This release line (${eol.verdict.cycle}) is past end of life${eol.verdict.eolDate ? ` (${eol.verdict.eolDate})` : ""}, so newer flaws will not be fixed either.`;
  if (eol.verdict.state === "approaching") return ` This release line (${eol.verdict.cycle}) reaches end of life on ${eol.verdict.eolDate}.`;
  return "";
}

export function buildServiceCveFindings(result: ServiceCveResult): Finding[] {
  const findings: Finding[] = [];
  for (const s of result.services) {
    const label = labelOf(s);
    const where = `port ${s.port}/${s.protocol}`;

    if (s.state === "version_unknown" && s.product) {
      findings.push({
        checkId: `${SERVICE_VERSION_UNKNOWN_CHECK}:${s.port}`,
        severity: "info",
        title: `[network] ${label} on ${where}: version unknown`,
        detail: `Service detection identified ${label} on ${where} but its banner does not show a version, so it was not matched against known CVEs. A missing version is not evidence that the service is up to date.`,
        metadata: { cpe: s.cpe },
      });
    }

    for (const m of s.matches) {
      const version = s.version ?? "";
      const cvss = m.cvssScore !== null ? ` CVSS${m.cvssVersion ? ` ${m.cvssVersion}` : ""} base score ${m.cvssScore}.` : "";
      const distro = s.packagedBy
        ? ` The banner names ${s.packagedBy}, which backports security fixes without changing the upstream version number, so this may already be fixed: confirm in ${s.packagedBy}'s security tracker.`
        : "";
      const finding: Finding = {
        checkId: `${SERVICE_CVE_CHECK}:${s.port}:${m.cveId}`,
        severity: s.packagedBy ? "info" : severityForCvss(m.cvssScore),
        title: `[network] ${label} ${version} on ${where}: ${m.cveId}`,
        detail:
          `Service detection identified ${label} ${version} on ${where} (CPE ${s.cpe}). NVD lists ${m.cveId} for ${m.matchedCriteria}` +
          ` in the version range ${m.range}, which includes ${version}.${cvss}${m.summary ? ` ${m.summary}` : ""}${eolSentence(s.eol)}${distro}`,
        remediation: serviceCveRemediation(label, version, s.port, m.cveId, s.packagedBy),
        cveIds: [m.cveId],
        metadata: {
          serviceCpe: s.cpe,
          comparedVersion: version,
          matchedCriteria: m.matchedCriteria,
          versionRange: m.range,
          packagedBy: s.packagedBy,
          indexedThrough: result.status === "checked" ? result.indexedThrough : null,
        },
      };
      if (m.cvssScore !== null && m.cvssVersion?.startsWith("3")) {
        finding.cvssScore = m.cvssScore;
        if (m.cvssVector) finding.cvssVector = m.cvssVector;
      }
      findings.push(finding);
    }

    if (s.eol.state === "checked" && s.eol.verdict?.state === "unsupported" && s.version) {
      const v = s.eol.verdict;
      findings.push({
        checkId: `${SERVICE_EOL_CHECK}:${s.port}`,
        severity: eolSeverity("platform", v.daysOverdue, s.packagedBy),
        title: `[network] ${s.eol.label} ${s.version} on ${where} is past end of life`,
        detail:
          `Service detection identified ${s.eol.label} ${s.version} on ${where}. endoflife.date lists the ${v.cycle} release line as end of life` +
          `${v.eolDate ? ` since ${v.eolDate}` : ""}: it no longer receives security fixes.` +
          (s.packagedBy ? ` The banner names ${s.packagedBy}, whose own support window may still cover it.` : ""),
        remediation: endOfLifeRemediation(s.eol.label, v.cycle, v.eolDate, s.eol.product, s.packagedBy),
        metadata: { serviceCpe: s.cpe, packagedBy: s.packagedBy },
      });
    }
  }
  return findings;
}

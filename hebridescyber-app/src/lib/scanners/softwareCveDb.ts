// CVE enrichment for the three fingerprint.ts riskySoftware entries osv.ts's
// own header comment explicitly excludes: WordPress core, PHP, and Apache.
// None of them are npm packages, so OSV.dev has no reliable single ecosystem
// to query for them (see ./osv.ts's header). This module closes that gap
// with two real data sources instead of one generalised OSV call:
//
// - WordPress core: WPScan's `/wordpresses/{version}` endpoint — the same
//   API wpvdb.ts already uses for WordPress *plugin* vulnerabilities, keyed
//   by version instead of slug. Same WPSCAN_API_TOKEN, same auth header,
//   same response shape (`{ "<version>": { vulnerabilities: [...] } }`).
// - PHP / Apache: NIST's NVD CVE API 2.0, queried by CPE name
//   (`cpeName=cpe:2.3:a:<vendor>:<product>:<version>:...`) rather than the
//   date-range query src/lib/newsletter.ts's fetchRecentHighSeverityCves
//   uses — same endpoint, same User-Agent/timeout discipline, different
//   query shape.
//
// Enrichment only, exactly like wpvdb.ts: this module does no detection of
// its own. It's called from src/lib/scanners/index.ts after fingerprint.ts
// resolves, keyed off its riskySoftware array. Never throws — every check
// degrades to no findings rather than failing the scan (see
// docs/SCANNER-CONVENTIONS.md rule 4 and this codebase's universal
// never-throw contract for scanner modules).
import type { Finding } from "./index";
import type { RiskyTech } from "./fingerprint";
import { vulnerabilityAppliesToVersion, wpVulnSeverity } from "./wpvdb";

const WPSCAN_API_BASE = "https://wpscan.com/api/v3";
const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
// Every outbound request in this codebase carries AbortSignal.timeout() so a
// hung third party can't hang a scan (docs/SCANNER-CONVENTIONS.md).
const REQUEST_TIMEOUT_MS = 8_000;
const NVD_TIMEOUT_MS = 15_000;
const NVD_USER_AGENT = "HebridesCyberBot/1.0 (+https://hebridescyber.co.uk)";

// NVD's public unauthenticated rate limit is 5 requests/30s (same limit
// src/lib/newsletter.ts's fetchRecentHighSeverityCves documents). This
// module calls NVD at most twice per scan (PHP once, Apache once, only when
// fingerprint.ts actually detected a risky version of each) — well inside
// that limit, so no client-side throttling is needed here.

// ---- WordPress core (WPScan) -----------------------------------------------

// Same raw shape wpvdb.ts's fetchPluginVulnerabilities parses, just keyed by
// version instead of plugin slug.
type WpScanVulnerability = {
  id?: number;
  title?: string;
  fixed_in?: string | null;
  vuln_type?: string;
  references?: { url?: string[]; cve?: string[] };
};
type WpScanCoreResponse = Record<string, { vulnerabilities?: WpScanVulnerability[] } | undefined>;

async function fetchWordPressCoreVulnerabilities(version: string, token: string): Promise<WpScanVulnerability[] | null> {
  try {
    const res = await fetch(`${WPSCAN_API_BASE}/wordpresses/${encodeURIComponent(version)}`, {
      headers: { Authorization: `Token token=${token}` },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    // WPScan doesn't track this exact version string — not an error, just
    // nothing to report.
    if (res.status === 404) return [];
    if (!res.ok) return null;
    const body = (await res.json()) as WpScanCoreResponse;
    return body[version]?.vulnerabilities ?? [];
  } catch {
    return null;
  }
}

/**
 * Looks up real CVE-backed vulnerabilities for a detected WordPress core
 * version via WPScan's Vulnerability Database. Gated on WPSCAN_API_TOKEN —
 * returns [] silently (not a status of its own) when unset, since this
 * function is only ever called from checkSoftwareCveDb() when a WordPress
 * version was already detected, and the orchestrator folds "not configured"
 * into its overall result rather than treating it as a distinct outcome per
 * software item.
 *
 * Same "skip rather than guess" version-matching discipline as wpvdb.ts:
 * a vulnerability only applies when its fixed_in is null (still unpatched
 * upstream) or the detected version numerically precedes it.
 */
export async function checkWordPressCoreCves(version: string): Promise<Finding[]> {
  const token = process.env.WPSCAN_API_TOKEN;
  if (!token) return [];

  const raw = await fetchWordPressCoreVulnerabilities(version, token);
  if (!raw || raw.length === 0) return [];

  const applicable = raw.filter((v) => vulnerabilityAppliesToVersion(v, version));
  if (applicable.length === 0) return [];

  return applicable.map((v) => {
    const id = v.id !== undefined ? String(v.id) : "unknown";
    const cveIds = (v.references?.cve ?? []).map((c) => (c.toUpperCase().startsWith("CVE-") ? c.toUpperCase() : `CVE-${c}`));
    const fixedIn = v.fixed_in ?? null;
    const title = v.title ?? `Vulnerability in WordPress core`;
    return {
      checkId: `softwareCveDb.wordpressCore:${id}`,
      severity: wpVulnSeverity(v.vuln_type ?? null),
      title: `WordPress core ${version} — ${title}`,
      detail: fixedIn
        ? `WPScan's vulnerability database lists this as fixed in version ${fixedIn} — the detected version ${version} predates that fix.${v.vuln_type ? ` Vulnerability type: ${v.vuln_type}.` : ""}`
        : `WPScan's vulnerability database lists this as still unpatched upstream as of its last update — no fixed version exists yet.${v.vuln_type ? ` Vulnerability type: ${v.vuln_type}.` : ""}`,
      cveIds,
    } satisfies Finding;
  });
}

// ---- Generic NVD CPE lookup (PHP / Apache) ---------------------------------

type NvdCveEntry = {
  id?: string;
  descriptions?: Array<{ lang?: string; value?: string }>;
  metrics?: {
    cvssMetricV31?: Array<{ cvssData?: { baseScore?: number } }>;
    cvssMetricV30?: Array<{ cvssData?: { baseScore?: number } }>;
    cvssMetricV2?: Array<{ cvssData?: { baseScore?: number } }>;
  };
};

type NvdParsedCve = { cveId: string; description: string; cvssScore: number | null };

const NVD_BUNDLE_CAP = 30;

function severityFromCvss(maxScore: number | null): Finding["severity"] {
  if (maxScore === null) return "medium";
  if (maxScore >= 9) return "critical";
  if (maxScore >= 7) return "high";
  return "medium";
}

async function fetchNvdCvesForCpe(cpeName: string): Promise<NvdParsedCve[] | null> {
  try {
    const url = `${NVD_API_BASE}?cpeName=${encodeURIComponent(cpeName)}&resultsPerPage=50`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(NVD_TIMEOUT_MS),
      headers: { "User-Agent": NVD_USER_AGENT },
    });
    if (!res.ok) return null;

    const json = (await res.json()) as { vulnerabilities?: Array<{ cve?: NvdCveEntry }> };
    return (json.vulnerabilities ?? []).map((v) => {
      const cve = v.cve;
      const cvssV31 = cve?.metrics?.cvssMetricV31?.[0]?.cvssData;
      const cvssV30 = cve?.metrics?.cvssMetricV30?.[0]?.cvssData;
      const cvssV2 = cve?.metrics?.cvssMetricV2?.[0]?.cvssData;
      const score = cvssV31?.baseScore ?? cvssV30?.baseScore ?? cvssV2?.baseScore ?? null;
      return {
        cveId: cve?.id ?? "",
        description: (cve?.descriptions ?? []).find((d) => d.lang === "en")?.value ?? "",
        cvssScore: score,
      };
    }).filter((c) => c.cveId);
  } catch {
    return null;
  }
}

/**
 * Generic NVD CPE-based CVE lookup, used for both PHP and Apache with
 * different vendor/product CPE strings. Bundles every matched CVE into a
 * single Finding rather than one Finding per CVE — an old PHP/Apache
 * install can easily have dozens of matches, and one Finding per CVE would
 * flood a scan report. Severity is derived from the highest CVSS score
 * across all matched CVEs (>= 9 critical, >= 7 high, else medium), and
 * cveIds is capped at NVD_BUNDLE_CAP so the finding stays a reasonable size
 * even when NVD returns far more.
 */
export async function checkNvdCpeVulnerabilities(
  vendor: string,
  product: string,
  version: string,
  displayName: string
): Promise<Finding[]> {
  const cpeName = `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;
  const cves = await fetchNvdCvesForCpe(cpeName);
  if (!cves || cves.length === 0) return [];

  const sorted = [...cves].sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0));
  const maxScore = sorted[0]?.cvssScore ?? null;
  const cveIds = sorted.map((c) => c.cveId).slice(0, NVD_BUNDLE_CAP);
  const totalCount = sorted.length;

  return [
    {
      checkId: `softwareCveDb.nvdCpe:${vendor}-${product}:${version}`,
      severity: severityFromCvss(maxScore),
      title: `${totalCount} known CVE(s) for ${displayName} ${version}`,
      detail:
        `NVD lists ${totalCount} CVE(s) matching ${displayName} ${version}` +
        (totalCount > cveIds.length ? ` (top ${cveIds.length} by CVSS score shown)` : "") +
        (maxScore !== null ? `. Highest CVSS score: ${maxScore}.` : ".") +
        (sorted[0]?.description ? ` Example: ${sorted[0].description}` : ""),
      cveIds,
    } satisfies Finding,
  ];
}

// ---- Orchestration ----------------------------------------------------------

export type SoftwareCveDbResult =
  | { status: "checked"; findings: Finding[] }
  | { status: "not_applicable"; note: string }
  | { status: "error"; note: string };

/**
 * fingerprint.ts / webapp.ts technology name → its NVD CPE vendor:product.
 * Used here for PHP and Apache, and by src/lib/emergingThreats.ts to read
 * which of our detected technologies a newly exploited CVE's NVD
 * configurations cover.
 *
 * Every entry was checked against a real NVD CVE record's configurations
 * (services.nvd.nist.gov/rest/json/cves/2.0?cveId=…) before being added — the
 * CVE named beside each one. Products are written exactly as they appear in
 * the CPE string, CPE escaping included (Joomla's is "joomla\!"). A wrong
 * entry would silently match nothing, so don't add one from memory.
 */
export const NVD_CPE_BY_NAME: Record<string, { vendor: string; product: string }> = {
  PHP: { vendor: "php", product: "php" }, // CVE-2024-4577
  // "http_server" is Apache httpd's real NIST CPE dictionary product name —
  // not "apache" or "httpd".
  Apache: { vendor: "apache", product: "http_server" }, // CVE-2021-41773, CVE-2021-42013
  // NVD moved nginx to F5's vendor name; even CVE-2013-2028 now reads f5:nginx.
  Nginx: { vendor: "f5", product: "nginx" }, // CVE-2021-23017, CVE-2022-41741
  IIS: { vendor: "microsoft", product: "internet_information_services" }, // CVE-2017-7269
  WordPress: { vendor: "wordpress", product: "wordpress" }, // CVE-2022-21661
  Drupal: { vendor: "drupal", product: "drupal" }, // CVE-2018-7600
  Joomla: { vendor: "joomla", product: "joomla\\!" }, // CVE-2023-23752
  // Checked against NVD's CVE API (virtualMatchString, 2026-10-19): TYPO3 473
  // CVEs, Moodle 641, Umbraco 57 (4 under "umbraco:umbraco"), Craft 97,
  // PrestaShop 95, OpenCart 39.
  TYPO3: { vendor: "typo3", product: "typo3" },
  Moodle: { vendor: "moodle", product: "moodle" },
  Umbraco: { vendor: "umbraco", product: "umbraco_cms" },
  "Craft CMS": { vendor: "craftcms", product: "craft_cms" },
  PrestaShop: { vendor: "prestashop", product: "prestashop" },
  OpenCart: { vendor: "opencart", product: "opencart" },
  jQuery: { vendor: "jquery", product: "jquery" }, // CVE-2020-11023
  Bootstrap: { vendor: "getbootstrap", product: "bootstrap" }, // CVE-2019-8331
  // AngularJS (1.x) is "angularjs:angularjs", not "angular.js".
  AngularJS: { vendor: "angularjs", product: "angularjs" }, // CVE-2022-25844
  Angular: { vendor: "angular", product: "angular" }, // CVE-2021-4231
  Lodash: { vendor: "lodash", product: "lodash" }, // CVE-2021-23337
  "Moment.js": { vendor: "momentjs", product: "moment" }, // CVE-2022-24785
  "Underscore.js": { vendor: "underscorejs", product: "underscore" }, // CVE-2021-23358
};

/**
 * Enriches fingerprint.ts's riskySoftware entries with real CVE data for
 * the three software families OSV.dev doesn't cover: WordPress core, PHP,
 * and Apache. Returns not_applicable when none of those three appear in
 * riskySoftware — this module has nothing to say about jQuery, Bootstrap,
 * Angular, etc. from KNOWN_RISKY, which are out of scope here.
 *
 * Runs each applicable lookup independently via Promise.allSettled so one
 * failing lookup (WPScan down, NVD rate-limited) never suppresses findings
 * from the others. Never throws — same contract as every scanner module.
 */
export async function checkSoftwareCveDb(riskySoftware: RiskyTech[]): Promise<SoftwareCveDbResult> {
  try {
    const wordpress = riskySoftware.find((r) => r.name === "WordPress");
    const php = riskySoftware.find((r) => r.name === "PHP");
    const apache = riskySoftware.find((r) => r.name === "Apache");

    if (!wordpress && !php && !apache) {
      return { status: "not_applicable", note: "No WordPress core, PHP, or Apache version was flagged as risky by fingerprint.ts." };
    }

    const tasks: Promise<Finding[]>[] = [];
    if (wordpress?.version) tasks.push(checkWordPressCoreCves(wordpress.version));
    if (php?.version) {
      const cpe = NVD_CPE_BY_NAME.PHP;
      tasks.push(checkNvdCpeVulnerabilities(cpe.vendor, cpe.product, php.version, "PHP"));
    }
    if (apache?.version) {
      const cpe = NVD_CPE_BY_NAME.Apache;
      tasks.push(checkNvdCpeVulnerabilities(cpe.vendor, cpe.product, apache.version, "Apache"));
    }

    if (tasks.length === 0) {
      return { status: "not_applicable", note: "WordPress, PHP, or Apache were flagged as risky, but none had a detected version to look up." };
    }

    const settled = await Promise.allSettled(tasks);
    const findings: Finding[] = [];
    for (const result of settled) {
      if (result.status === "fulfilled") findings.push(...result.value);
      // A rejected task contributes nothing — never throws the whole check.
    }

    return { status: "checked", findings };
  } catch (err) {
    return { status: "error", note: `Software CVE lookup failed: ${(err as Error).message}` };
  }
}

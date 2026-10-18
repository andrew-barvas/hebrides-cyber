// WPScan Vulnerability Database lookup for WordPress plugins detected by
// webapp.ts's checkWordPress(). Closes a gap flagged in that module's own
// comments and in index.ts's original wp-plugin-detected finding: OSV.dev
// has no WordPress plugin ecosystem coverage, so a detected plugin version
// was previously reported with no automated CVE match at all — "Elementor
// 3.6 detected, go check yourself manually." WPScan's vulnerability
// database is exactly the missing data source (the same one the WPScan CLI
// tool itself uses).
//
// Requires WPSCAN_API_TOKEN — free tier available (25 requests/day at the
// time this was written; see https://wpscan.com/api). Never throws;
// missing token or any API failure degrades to not_configured/error with
// no findings, same contract as every other scanner module.
//
// This module does no detection of its own — it only enriches the plugins
// webapp.ts already found via readme.txt "Stable tag" probing against its
// curated PLUGIN_CANDIDATES list, which is why the query count per scan is
// naturally small (that list is capped at 20 slugs, and only installed
// ones make it into the plugins array passed in here).
//
// VERSION MATCHING: WPScan's vulnerabilities carry a fixed_in version (or
// null for "still unpatched upstream"). A vulnerability is reported against
// the detected install only when fixed_in is null (unambiguously still
// vulnerable) or the detected version numerically precedes fixed_in via
// compareVersions' lenient dotted-numeric compare. Matching this codebase's
// established "skip rather than guess" discipline (dependencyManifest.ts,
// generate-fix-pr.ts's dependency-bump safety gate): if either version
// string has a non-numeric segment, that vulnerability is left out for that
// plugin rather than guessed at — never a fabricated finding.
import type { Finding } from "./index";
import type { DetectedPlugin } from "./webapp";

const WPSCAN_API_BASE = "https://wpscan.com/api/v3";
// Every outbound request in this codebase carries AbortSignal.timeout() so a
// hung third party can't hang a scan (docs/SCANNER-CONVENTIONS.md).
const REQUEST_TIMEOUT_MS = 8_000;
const QUERY_CONCURRENCY = 5;

export type WpVulnDbVulnerability = {
  id: string;
  title: string;
  /** null means "no patched version exists yet" — still unpatched upstream. */
  fixedIn: string | null;
  vulnType: string | null;
  cveIds: string[];
  referenceUrls: string[];
};

export type WpVulnDbPluginResult = {
  slug: string;
  name: string;
  version: string;
  vulnerabilities: WpVulnDbVulnerability[];
};

export type WpVulnDbResult =
  /** themes: optional because results stored before theme lookups lack it. */
  | { status: "checked"; plugins: WpVulnDbPluginResult[]; themes?: WpVulnDbPluginResult[] }
  | { status: "not_applicable"; note: string }
  | { status: "not_configured"; note: string }
  | { status: "error"; note: string };

// Raw shape (subset) of GET /plugins/{slug} — see https://wpscan.com/api
type WpScanVulnerability = {
  id?: number;
  title?: string;
  fixed_in?: string | null;
  vuln_type?: string;
  references?: { url?: string[]; cve?: string[] };
};
type WpScanPluginResponse = Record<string, { vulnerabilities?: WpScanVulnerability[] } | undefined>;

/**
 * Lenient dotted-numeric version compare (a < b => negative, a > b => positive,
 * equal => 0). Returns null — "not comparable" — rather than guessing when
 * either string contains a segment that isn't a plain number, since WordPress
 * plugin versions aren't guaranteed strict semver.
 */
export function compareVersions(a: string, b: string): number | null {
  const pa = a.trim().replace(/^v/i, "").split(".");
  const pb = b.trim().replace(/^v/i, "").split(".");
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = Number(pa[i] ?? "0");
    const nb = Number(pb[i] ?? "0");
    if (!Number.isFinite(na) || !Number.isFinite(nb)) return null;
    if (na !== nb) return na - nb;
  }
  return 0;
}

export function vulnerabilityAppliesToVersion(vuln: WpScanVulnerability, installedVersion: string): boolean {
  if (!vuln.fixed_in) return true; // still unpatched upstream — applies regardless of version
  const cmp = compareVersions(installedVersion, vuln.fixed_in);
  if (cmp === null) return false; // can't evidence it — skip rather than guess
  return cmp < 0; // installed strictly precedes the fixed version
}

/** Real RCE/SQLi/priv-esc classes read as critical; everything else WPScan
 *  reports (XSS, CSRF, info disclosure, etc.) reads as high — a confirmed,
 *  disclosed vulnerability in software this site is actually running,
 *  regardless of exact exploitability nuance. */
export function wpVulnSeverity(vulnType: string | null): Finding["severity"] {
  const t = (vulnType ?? "").toUpperCase();
  if (["SQLI", "RCE", "PRIVESC", "AUTHBYPASS"].some((k) => t.includes(k))) return "critical";
  return "high";
}

async function fetchPluginVulnerabilities(slug: string, token: string, kind: "plugins" | "themes" = "plugins"): Promise<WpScanVulnerability[] | null> {
  try {
    const res = await fetch(`${WPSCAN_API_BASE}/${kind}/${encodeURIComponent(slug)}`, {
      headers: { Authorization: `Token token=${token}` },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    // WPScan doesn't track this slug (or it's spelled differently in their
    // DB than in wp.org's) — not an error, just nothing to report.
    if (res.status === 404) return [];
    if (!res.ok) return null;
    const body = (await res.json()) as WpScanPluginResponse;
    return body[slug]?.vulnerabilities ?? [];
  } catch {
    return null;
  }
}

async function mapWithConcurrency<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let index = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (index < items.length) {
      const i = index++;
      results[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return results;
}

export async function checkWpVulnDb(plugins: DetectedPlugin[], themes: DetectedPlugin[] = []): Promise<WpVulnDbResult> {
  const token = process.env.WPSCAN_API_TOKEN;
  if (!token) {
    return { status: "not_configured", note: "WPSCAN_API_TOKEN is not set — skipping WordPress plugin CVE lookup. See .env.example." };
  }
  if (plugins.length === 0 && themes.length === 0) {
    return { status: "not_applicable", note: "No WordPress plugins or themes were detected to look up." };
  }

  try {
    const items = [
      ...plugins.map((p) => ({ item: p, kind: "plugins" as const })),
      ...themes.map((t) => ({ item: t, kind: "themes" as const })),
    ];
    const lookups = await mapWithConcurrency(items, QUERY_CONCURRENCY, async ({ item, kind }) => ({
      plugin: item,
      kind,
      raw: await fetchPluginVulnerabilities(item.slug, token, kind),
    }));

    // A failed lookup (rate limit — the free tier allows 25 a day — a revoked
    // token, an outage) is not "no vulnerabilities". Reporting it as checked
    // would let this scan mark last scan's plugin findings fixed and close
    // their tickets, so any failure makes the whole check an error.
    const failed = lookups.filter((l) => l.raw === null).map((l) => l.plugin.slug);
    if (failed.length > 0) {
      return { status: "error", note: `WPScan lookup failed for ${failed.length} of ${items.length} plugin(s)/theme(s): ${failed.join(", ")}` };
    }

    const results = lookups.map(({ plugin, kind, raw }) => {
      const vulnerabilities: WpVulnDbVulnerability[] = (raw ?? [])
        .filter((v) => vulnerabilityAppliesToVersion(v, plugin.version))
        .map((v) => ({
          id: v.id !== undefined ? String(v.id) : "unknown",
          title: v.title ?? `Vulnerability in ${plugin.name}`,
          fixedIn: v.fixed_in ?? null,
          vulnType: v.vuln_type ?? null,
          cveIds: (v.references?.cve ?? []).map((c) => (c.toUpperCase().startsWith("CVE-") ? c.toUpperCase() : `CVE-${c}`)),
          referenceUrls: v.references?.url ?? [],
        }));
      return { kind, result: { slug: plugin.slug, name: plugin.name, version: plugin.version, vulnerabilities } };
    });

    return {
      status: "checked",
      plugins: results.filter((r) => r.kind === "plugins").map((r) => r.result),
      themes: results.filter((r) => r.kind === "themes").map((r) => r.result),
    };
  } catch (err) {
    return { status: "error", note: `WPScan lookup failed: ${(err as Error).message}` };
  }
}

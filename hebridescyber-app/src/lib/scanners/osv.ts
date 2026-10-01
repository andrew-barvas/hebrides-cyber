// CVE enrichment via OSV.dev (https://osv.dev) — free, keyless, covers npm
// among other ecosystems. Scoped deliberately to src/lib/scanners/webapp.ts's
// JS library detection, not fingerprint.ts's broader riskySoftware: jQuery,
// Lodash, Bootstrap etc. map cleanly to real npm package names, but
// fingerprint.ts also flags things like WordPress core, PHP, and Apache —
// none of which are npm packages, and OSV has no reliable single ecosystem
// for "WordPress core version X". Forcing that mapping would produce mostly
// empty or wrong results, which is worse than no CVE data at all.
//
// The existing static vulnerableBelow/reason logic in webapp.ts stays the
// source of truth for WHETHER a finding is raised — this module only adds
// cveIds to a finding that's already been flagged, and never changes whether
// something gets flagged. If OSV is unreachable or returns nothing, the
// finding still fires; it just carries fewer (or zero) CVE ids.
//
// The second half of this file (queryOsvBatch / fetchOsvVulnDetails) is
// the bulk path src/lib/scanners/dependencyManifest.ts uses for whole
// lockfiles: one POST /v1/querybatch for up to 1000 packages, then
// GET /v1/vulns/{id} for each advisory it names. Unlike the single-package
// helpers above it, a failed batch is reported as a failure, never as "no
// vulnerabilities" — the caller turns it into an "error" result.

import { compareEcosystemVersions } from "./ecosystemVersion";

// Display name (from LIB_PATTERNS in webapp.ts) -> real npm package name.
// Not every detected library has a meaningful npm equivalent — Prototype.js
// has no actively maintained npm package worth querying, so it's omitted
// rather than guessing a name that would return nothing anyway.
const NPM_PACKAGE_NAMES: Record<string, string> = {
  "jQuery": "jquery",
  "Moment.js": "moment",
  "Lodash": "lodash",
  "Underscore.js": "underscore",
  "Bootstrap": "bootstrap",
  "AngularJS": "angular",
};

export function npmPackageNameFor(displayName: string): string | null {
  return NPM_PACKAGE_NAMES[displayName] ?? null;
}

// OSV's own `id` is frequently a GHSA-xxxx (GitHub Security Advisory) or
// OSV-xxxx identifier, not a CVE — the actual CVE, when one exists, commonly
// shows up only in `aliases`. Checking `id` alone would silently under-report
// real, well-known CVEs for advisories sourced from GHSA.
type OsvVuln = { id: string; summary?: string; aliases?: string[] };

type OsvRangeEvent = { introduced?: string; fixed?: string; last_affected?: string; limit?: string };
type OsvRange = { type?: string; events?: OsvRangeEvent[] };
type OsvAffected = { package?: { name?: string; ecosystem?: string; purl?: string }; ranges?: OsvRange[]; versions?: string[] };

/** The parts of an OSV.dev vulnerability record (https://ossf.github.io/osv-schema/) this app reads. */
export type OsvVulnDetail = OsvVuln & {
  modified?: string;
  withdrawn?: string;
  severity?: Array<{ type?: string; score?: string }>;
  database_specific?: { severity?: unknown } & Record<string, unknown>;
  affected?: OsvAffected[];
};

const OSV_API = "https://api.osv.dev/v1";
const OSV_TIMEOUT_MS = 5_000;
// A 1000-package batch is one request; OSV.dev answers it in a few seconds
// normally, so this is generous rather than tight.
const OSV_BATCH_TIMEOUT_MS = 30_000;
// OSV.dev paginates a package with very many advisories (next_page_token).
// Ten pages is far beyond any real package; past it we report the lookup as
// incomplete rather than looping forever.
const MAX_QUERY_PAGES = 10;

const isCve = (id: string) => /^CVE-\d{4}-\d{4,}$/i.test(id);

/** CVE ids from an advisory's own id and its aliases, upper-cased and de-duplicated. */
export function cveIdsOf(vulns: OsvVuln[]): string[] {
  return [...new Set(vulns.flatMap((v) => [v.id, ...(v.aliases ?? [])]).filter((id) => typeof id === "string" && isCve(id)).map((id) => id.toUpperCase()))];
}

// Keyed by "ecosystem:package@version". Many customers run the same jQuery
// version, so this avoids a redundant OSV round-trip per scan within one warm
// process — best-effort only, there's no persistence or eviction, since
// serverless instances are short-lived anyway and this is a cheap win, not a
// cache layer worth building infrastructure for.
const cache = new Map<string, string[]>();

/** Extracts any CVE ids already present in free text — the fallback when a
 *  live OSV lookup fails or returns nothing, since webapp.ts's static
 *  `reason` strings already name specific CVEs for several libraries. */
export function extractCveIdsFromText(text: string): string[] {
  const matches = text.match(/CVE-\d{4}-\d{4,}/gi) ?? [];
  return [...new Set(matches.map((m) => m.toUpperCase()))];
}

/**
 * Every advisory OSV.dev lists for one package@version, following
 * `next_page_token` (OSV.dev pages a package with many advisories — reading
 * only the first page used to cut the list off silently). Null on any
 * failure, including a page past the first: a partial list must not be
 * mistaken for the whole one.
 */
async function queryAllPages(ecosystem: string, packageName: string, version: string): Promise<OsvVulnDetail[] | null> {
  const vulns: OsvVulnDetail[] = [];
  let pageToken: string | undefined;
  for (let page = 0; page < MAX_QUERY_PAGES; page++) {
    const res = await fetch(`${OSV_API}/query`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ package: { name: packageName, ecosystem }, version, ...(pageToken ? { page_token: pageToken } : {}) }),
      signal: AbortSignal.timeout(OSV_TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { vulns?: OsvVulnDetail[]; next_page_token?: string };
    vulns.push(...(body.vulns ?? []));
    if (!body.next_page_token) return vulns;
    pageToken = body.next_page_token;
  }
  return null;
}

/**
 * Looks up known vulnerabilities for a package/version in an arbitrary OSV.dev
 * ecosystem (e.g. "npm", "PyPI", "Packagist"). OSV.dev's query API accepts any
 * ecosystem string in this same request shape.
 *
 * Never throws — a failed or empty lookup returns [], the caller is expected
 * to fall back to extractCveIdsFromText on its own static reason text where
 * one exists (webapp.ts). dependencyManifest.ts no longer uses this: it needs
 * "failed" and "nothing found" told apart, which queryOsvBatch does.
 */
export async function lookupCveIds(ecosystem: string, packageName: string, version: string): Promise<string[]> {
  if (version === "unknown") return [];

  const cacheKey = `${ecosystem}:${packageName}@${version}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  try {
    const vulns = await queryAllPages(ecosystem, packageName, version);
    if (!vulns) return [];
    // Check both `id` and `aliases` — see the type comment above for why.
    const ids = cveIdsOf(vulns);
    cache.set(cacheKey, ids);
    return ids;
  } catch {
    return [];
  }
}

/** Thin npm-specific wrapper, kept so webapp.ts's existing call sites and the
 *  local verification precedent (lodash 4.17.15 → 6 real CVEs) never change. */
export async function lookupNpmCveIds(packageName: string, version: string): Promise<string[]> {
  return lookupCveIds("npm", packageName, version);
}

// ---------------------------------------------------------------------------
// Fix-version lookup, added for src/pages/api/generate-fix-pr.ts's dependency
// bump feature, and reused by dependencyManifest.ts to name the fixed version
// in a finding.
//
// OSV.dev's `affected[].ranges[].events` array names a `"fixed"` version per
// range (confirmed against a live https://api.osv.dev/v1/query response for
// lodash@4.17.15, which returns
// `"ranges":[{"type":"SEMVER","events":[{"introduced":"4.0.0"},{"fixed":"4.17.21"}]}]`
// under the `affected` entry whose `package.name` is "lodash" — the same
// response also contains `affected` entries for unrelated packages like
// "lodash-es" and "lodash.trimend" that must be filtered out by name).
//
// npm, Go and crates.io advisories use SEMVER ranges; PyPI, Maven, RubyGems,
// NuGet and Packagist use ECOSYSTEM ranges, ordered by that ecosystem's own
// rules. Only SEMVER used to be read, so every PyPI/Maven fix version was
// lost; both are now compared through ecosystemVersion.ts. GIT ranges
// (commit hashes) can't be compared with a version and are skipped.
//
// A `"fixed"` event is a real patched version. Its absence (only
// `"last_affected"`, or no matching range at all) means OSV.dev does not know
// of one yet — that is exactly the "don't guess" case the caller's safety
// gate must skip.

export type OsvFixInfo = {
  cveIds: string[];
  /** Raw OSV.dev advisory ids (e.g. "GHSA-…" or "OSV-…") — every advisory has
   *  one of these even when it has no CVE alias, and https://osv.dev/vulnerability/<id>
   *  is a valid page for each, unlike CVE ids which OSV.dev doesn't host directly. */
  osvIds: string[];
  /**
   * The lowest version that resolves every vulnerability OSV.dev reports for
   * this package at the queried version, or null when at least one of them
   * has no named fixed version (still unpatched upstream, or the only event
   * is `last_affected`) — callers must treat null as "cannot determine a
   * safe target version," never as "no fix needed." May carry a prerelease
   * or ecosystem-specific suffix ("2.0.0rc1", "32.0.0-android"); a caller
   * that writes it into a manifest must check the shape it needs.
   */
  fixedVersion: string | null;
};

const fixCache = new Map<string, OsvFixInfo>();

const cmp = (ecosystem: string, a: string, b: string) => compareEcosystemVersions(ecosystem, a, b);

/** OSV package names are case-insensitive for PyPI (PEP 503) and NuGet; exact elsewhere. */
export function osvNamesMatch(ecosystem: string, a: string, b: string): boolean {
  if (ecosystem === "PyPI") return normalisePyPiName(a) === normalisePyPiName(b);
  if (ecosystem === "NuGet" || ecosystem === "Packagist") return a.toLowerCase() === b.toLowerCase();
  return a === b;
}

/** PEP 503 name normalisation: lower-case, runs of "-", "_" and "." become one "-". */
export function normalisePyPiName(name: string): string {
  return name.trim().toLowerCase().replace(/[-_.]+/g, "-");
}

function rangesFor(vuln: OsvVulnDetail, ecosystem: string, packageName: string): OsvRange[] {
  return (vuln.affected ?? [])
    // "Ubuntu:22.04:LTS"-style ecosystem variants share the base name before ":".
    .filter((a) => (a.package?.ecosystem ?? "").split(":")[0] === ecosystem && osvNamesMatch(ecosystem, a.package?.name ?? "", packageName))
    .flatMap((a) => a.ranges ?? [])
    .filter((r) => r.type === "SEMVER" || r.type === "ECOSYSTEM");
}

/**
 * The fixed version(s) of whichever range actually contains `current` —
 * OSV lists one range per release branch (e.g. introduced 0 → fixed 3.10.2,
 * introduced 4.0.0 → fixed 4.17.21), and only the branch you're on says what
 * to upgrade *to*. An `introduced` of "0" means "from the beginning".
 */
function fixedInCurrentBranch(ecosystem: string, ranges: OsvRange[], current: string): string[] {
  const out: string[] = [];
  for (const range of ranges) {
    let introduced: string | null = "0";
    for (const event of range.events ?? []) {
      if (event.introduced !== undefined) introduced = event.introduced;
      if (event.fixed === undefined || introduced === null) continue;
      const afterStart = introduced === "0" ? 0 : cmp(ecosystem, current, introduced);
      const beforeFix = cmp(ecosystem, current, event.fixed);
      if (afterStart !== null && afterStart >= 0 && beforeFix !== null && beforeFix < 0) out.push(event.fixed);
    }
  }
  return out;
}

/**
 * The single version that fixes every advisory in `vulns` for this package,
 * or null when any of them has no fixed version OSV.dev can name (or none
 * this comparator can read). Pure — the shared core of lookupOsvFixInfo and
 * dependencyManifest.ts's lockfile findings.
 */
export function fixedVersionFromVulns(vulns: OsvVulnDetail[], ecosystem: string, packageName: string, version: string): string | null {
  if (vulns.length === 0) return null;
  const currentReadable = cmp(ecosystem, version, version) !== null;
  let best: string | null = null;

  for (const v of vulns) {
    const ranges = rangesFor(v, ecosystem, packageName);
    const allFixed = ranges
      .flatMap((r) => r.events ?? [])
      .map((e) => e.fixed)
      .filter((f): f is string => typeof f === "string" && cmp(ecosystem, f, f) !== null);

    // This vuln has no matching range with a readable fixed version —
    // either still unpatched, or only a last_affected event. We cannot
    // promise a single version fixes everything.
    if (allFixed.length === 0) return null;

    // Prefer the fix on the branch the package is actually on — the lowest
    // version that resolves this vuln. Taking the highest fix across every
    // branch (what this used to do) turned a 3.10.0 → 3.10.2 patch into a
    // breaking 3.x → 4.x upgrade PR. When the current version can't be
    // placed in a range, keep the conservative choice (highest fix) — but
    // never one at or below the installed version, which would be a
    // downgrade that fixes nothing.
    const inBranch = currentReadable ? fixedInCurrentBranch(ecosystem, ranges, version) : [];
    let pick: string;
    if (inBranch.length > 0) {
      pick = inBranch.reduce((lo, f) => ((cmp(ecosystem, f, lo) ?? 0) < 0 ? f : lo));
    } else {
      pick = allFixed.reduce((hi, f) => ((cmp(ecosystem, f, hi) ?? 0) > 0 ? f : hi));
      if (currentReadable && (cmp(ecosystem, pick, version) ?? 1) <= 0) return null;
    }

    if (best === null || (cmp(ecosystem, pick, best) ?? 0) > 0) best = pick;
  }
  return best;
}

/**
 * Looks up CVE ids plus a fixed-version target for a package/version, in the
 * same "npm" (or any OSV ecosystem) shape as lookupCveIds. Never throws — a
 * failed or empty lookup returns { cveIds: [], fixedVersion: null }, which
 * callers must treat as "cannot safely act," not "nothing wrong."
 */
export async function lookupOsvFixInfo(ecosystem: string, packageName: string, version: string): Promise<OsvFixInfo> {
  const empty: OsvFixInfo = { cveIds: [], osvIds: [], fixedVersion: null };
  if (version === "unknown") return empty;

  const cacheKey = `${ecosystem}:${packageName}@${version}`;
  const cached = fixCache.get(cacheKey);
  if (cached) return cached;

  try {
    const vulns = await queryAllPages(ecosystem, packageName, version);
    if (!vulns) return empty;
    if (vulns.length === 0) {
      fixCache.set(cacheKey, empty);
      return empty;
    }

    const result: OsvFixInfo = {
      cveIds: cveIdsOf(vulns),
      osvIds: [...new Set(vulns.map((v) => v.id).filter((id): id is string => typeof id === "string"))],
      fixedVersion: fixedVersionFromVulns(vulns, ecosystem, packageName, version),
    };
    fixCache.set(cacheKey, result);
    return result;
  } catch {
    return empty;
  }
}

// ---------------------------------------------------------------------------
// Severity, from the advisory itself.

type Severity = "critical" | "high" | "medium" | "low";

const CVSS3_WEIGHTS: Record<string, Record<string, number>> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
};

/** CVSS v3.1 "Roundup": the smallest one-decimal number >= x, without float drift. */
function roundUp1(x: number): number {
  const i = Math.round(x * 100_000);
  return i % 10_000 === 0 ? i / 100_000 : (Math.floor(i / 10_000) + 1) / 10;
}

/**
 * CVSS v3.0/v3.1 base score from a vector string ("CVSS:3.1/AV:N/AC:L/...").
 * Null for anything else (CVSS v2 or v4 vectors, missing metrics). OSV.dev
 * gives the vector, not the score.
 */
export function cvss3BaseScore(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const m: Record<string, string> = {};
  for (const part of vector.split("/").slice(1)) {
    const [k, v] = part.split(":");
    if (k && v) m[k] = v;
  }
  const scopeChanged = m.S === "C";
  if (m.S !== "U" && m.S !== "C") return null;
  const pr = m.PR === "N" ? 0.85 : m.PR === "L" ? (scopeChanged ? 0.68 : 0.62) : m.PR === "H" ? (scopeChanged ? 0.5 : 0.27) : undefined;
  const w = (k: string) => CVSS3_WEIGHTS[k]?.[m[k]];
  const [av, ac, ui, c, i, a] = [w("AV"), w("AC"), w("UI"), w("C"), w("I"), w("A")];
  if ([pr, av, ac, ui, c, i, a].some((x) => x === undefined)) return null;

  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  if (impact <= 0) return 0;
  return roundUp1(Math.min(scopeChanged ? 1.08 * (impact + exploitability) : impact + exploitability, 10));
}

function severityFromScore(score: number): Severity | null {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return null;
}

/** The advisory's highest CVSS v3 vector and score, when it publishes one. */
export function osvCvss(vuln: OsvVulnDetail): { vector: string; score: number } | null {
  let best: { vector: string; score: number } | null = null;
  for (const s of vuln.severity ?? []) {
    if (s.type !== "CVSS_V3" || typeof s.score !== "string") continue;
    const score = cvss3BaseScore(s.score);
    if (score !== null && (!best || score > best.score)) best = { vector: s.score, score };
  }
  return best;
}

/**
 * The advisory's own severity rating: GitHub's reviewed rating
 * (`database_specific.severity`, on every GHSA record) where present, else
 * its CVSS v3 vector's band. Null when the advisory rates itself neither way
 * (Go's database, for one, publishes no severity) — never a guess.
 */
export function osvSeverity(vuln: OsvVulnDetail): Severity | null {
  const rated = String(vuln.database_specific?.severity ?? "").toUpperCase();
  if (rated === "CRITICAL") return "critical";
  if (rated === "HIGH") return "high";
  if (rated === "MODERATE" || rated === "MEDIUM") return "medium";
  if (rated === "LOW") return "low";
  const cvss = osvCvss(vuln);
  return cvss ? severityFromScore(cvss.score) : null;
}

// ---------------------------------------------------------------------------
// Bulk path: POST /v1/querybatch + GET /v1/vulns/{id}.

export type OsvBatchQuery = { ecosystem: string; name: string; version: string };
export type OsvBatchResult = { ok: true; vulnIds: string[][] } | { ok: false; error: string };

/** OSV.dev's documented ceiling on queries per querybatch request. */
export const OSV_BATCH_MAX_QUERIES = 1000;

type BatchResponse = { results?: Array<{ vulns?: Array<{ id?: string }>; next_page_token?: string }> };

async function postBatch(queries: Array<OsvBatchQuery & { pageToken?: string }>): Promise<BatchResponse["results"] | string> {
  const body = JSON.stringify({
    queries: queries.map((q) => ({ package: { name: q.name, ecosystem: q.ecosystem }, version: q.version, ...(q.pageToken ? { page_token: q.pageToken } : {}) })),
  });
  let lastError = "";
  // One immediate retry for a transient failure (5xx, 429, network): a
  // failed batch fails the whole dependency check, so it's worth one more go.
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(`${OSV_API}/querybatch`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
        signal: AbortSignal.timeout(OSV_BATCH_TIMEOUT_MS),
      });
      if (!res.ok) {
        lastError = `OSV.dev querybatch returned HTTP ${res.status}`;
        if (res.status >= 500 || res.status === 429) continue;
        return lastError;
      }
      const parsed = (await res.json()) as BatchResponse;
      if (!Array.isArray(parsed.results) || parsed.results.length !== queries.length) {
        return `OSV.dev querybatch returned ${Array.isArray(parsed.results) ? parsed.results.length : "no"} results for ${queries.length} queries`;
      }
      return parsed.results;
    } catch (err) {
      lastError = `OSV.dev querybatch failed: ${(err as Error).message}`;
    }
  }
  return lastError;
}

/**
 * Advisory ids per query, in query order — OSV.dev's batch endpoint returns
 * only ids; fetchOsvVulnDetails reads the rest. Chunks into requests of at
 * most 1000 queries and follows each query's own `next_page_token`. Any
 * failed request (after one retry) fails the whole batch: { ok: false } is
 * "we don't know", and must never be read as "no vulnerabilities".
 */
export async function queryOsvBatch(queries: OsvBatchQuery[]): Promise<OsvBatchResult> {
  const vulnIds: string[][] = queries.map(() => []);
  let pending: Array<{ index: number; pageToken?: string }> = queries.map((_, index) => ({ index }));

  for (let round = 0; pending.length > 0; round++) {
    if (round >= MAX_QUERY_PAGES) {
      return { ok: false, error: `OSV.dev kept paginating after ${MAX_QUERY_PAGES} pages for ${pending.length} package(s); results would be incomplete` };
    }
    const next: typeof pending = [];
    for (let start = 0; start < pending.length; start += OSV_BATCH_MAX_QUERIES) {
      const chunk = pending.slice(start, start + OSV_BATCH_MAX_QUERIES);
      const results = await postBatch(chunk.map((p) => ({ ...queries[p.index], pageToken: p.pageToken })));
      if (typeof results === "string") return { ok: false, error: results };
      results!.forEach((r, i) => {
        const index = chunk[i].index;
        for (const v of r.vulns ?? []) if (typeof v.id === "string" && !vulnIds[index].includes(v.id)) vulnIds[index].push(v.id);
        if (r.next_page_token) next.push({ index, pageToken: r.next_page_token });
      });
    }
    pending = next;
  }
  return { ok: true, vulnIds };
}

// Advisory records change rarely and are shared by every package/version
// they cover, so one fetch per id per warm process is plenty. Only
// successful fetches are cached.
const vulnCache = new Map<string, OsvVulnDetail>();

/**
 * Full advisory records for `ids`, fetched with bounded concurrency. Ids
 * that couldn't be fetched come back in `failed` — the caller still knows
 * the package is affected (querybatch said so), it just lacks the detail.
 */
export async function fetchOsvVulnDetails(
  ids: string[],
  options: { concurrency?: number } = {}
): Promise<{ details: Map<string, OsvVulnDetail>; failed: string[] }> {
  const details = new Map<string, OsvVulnDetail>();
  const failed: string[] = [];
  const unique = [...new Set(ids)];
  let next = 0;

  const worker = async () => {
    while (next < unique.length) {
      const id = unique[next++];
      const cached = vulnCache.get(id);
      if (cached) {
        details.set(id, cached);
        continue;
      }
      try {
        const res = await fetch(`${OSV_API}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(OSV_TIMEOUT_MS) });
        if (!res.ok) {
          failed.push(id);
          continue;
        }
        const body = (await res.json()) as OsvVulnDetail;
        if (!body || typeof body.id !== "string") {
          failed.push(id);
          continue;
        }
        vulnCache.set(id, body);
        details.set(id, body);
      } catch {
        failed.push(id);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(options.concurrency ?? 10, unique.length) }, worker));
  return { details, failed: failed.sort() };
}

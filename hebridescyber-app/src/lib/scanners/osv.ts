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

const OSV_TIMEOUT_MS = 5_000;

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
 * Looks up known vulnerabilities for a package/version in an arbitrary OSV.dev
 * ecosystem (e.g. "npm", "PyPI", "Packagist"). OSV.dev's query API accepts any
 * ecosystem string in this same request shape — "npm" was just the only value
 * ever passed until src/lib/scanners/dependencyManifest.ts needed the same
 * lookup for manifest-based scanning.
 *
 * Never throws — a failed or empty lookup returns [], the caller is expected
 * to fall back to extractCveIdsFromText on its own static reason text where
 * one exists (webapp.ts), or to simply emit no finding (dependencyManifest.ts,
 * which has no static reason text to fall back to).
 */
export async function lookupCveIds(ecosystem: string, packageName: string, version: string): Promise<string[]> {
  if (version === "unknown") return [];

  const cacheKey = `${ecosystem}:${packageName}@${version}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ package: { name: packageName, ecosystem }, version }),
      signal: AbortSignal.timeout(OSV_TIMEOUT_MS),
    });
    if (!res.ok) return [];

    const body = (await res.json()) as { vulns?: OsvVuln[] };
    const isCve = (id: string) => /^CVE-\d{4}-\d{4,}$/i.test(id);

    // Check both `id` and `aliases` — see the type comment above for why.
    const ids = [
      ...new Set(
        (body.vulns ?? []).flatMap((v) => [v.id, ...(v.aliases ?? [])]).filter(isCve).map((id) => id.toUpperCase())
      ),
    ];

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
// bump feature. Deliberately a separate function/cache from lookupCveIds
// above rather than a change to its signature or return shape — every
// existing caller (webapp.ts, dependencyManifest.ts) keeps working unchanged.
//
// OSV.dev's `affected[].ranges[].events` array names a `"fixed"` version per
// SEMVER range (confirmed against a live https://api.osv.dev/v1/query
// response for lodash@4.17.15, which returns
// `"ranges":[{"type":"SEMVER","events":[{"introduced":"4.0.0"},{"fixed":"4.17.21"}]}]`
// under the `affected` entry whose `package.name` is "lodash" — the same
// response also contains `affected` entries for unrelated packages like
// "lodash-es" and "lodash.trimend" that must be filtered out by name).
//
// A `"fixed"` event is a real patched version. Its absence (only
// `"last_affected"`, or no matching range at all) means OSV.dev does not know
// of one yet — that is exactly the "don't guess" case the caller's safety
// gate must skip.

type OsvRangeEvent = { introduced?: string; fixed?: string; last_affected?: string };
type OsvRange = { type?: string; events?: OsvRangeEvent[] };
type OsvAffected = { package?: { name?: string; ecosystem?: string }; ranges?: OsvRange[] };
type OsvVulnFull = OsvVuln & { affected?: OsvAffected[] };

export type OsvFixInfo = {
  cveIds: string[];
  /** Raw OSV.dev advisory ids (e.g. "GHSA-…" or "OSV-…") — every advisory has
   *  one of these even when it has no CVE alias, and https://osv.dev/vulnerability/<id>
   *  is a valid page for each, unlike CVE ids which OSV.dev doesn't host directly. */
  osvIds: string[];
  /**
   * The lowest concrete version that resolves every vulnerability OSV.dev
   * reports for this package at the queried version, or null when at least
   * one of them has no named fixed version (still unpatched upstream, or the
   * only event is `last_affected`) — callers must treat null as "cannot
   * determine a safe target version," never as "no fix needed."
   */
  fixedVersion: string | null;
};

const fixCache = new Map<string, OsvFixInfo>();

/** Parses a bare `X.Y.Z` version for comparison. Anything with a prerelease/
 *  build suffix or non-numeric segment returns null — same "don't guess"
 *  posture as dependencyManifest.ts's minVersionFromRange. */
function parseConcreteVersion(v: string): [number, number, number] | null {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(v.trim());
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function compareConcreteVersions(a: [number, number, number], b: [number, number, number]): number {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

/**
 * The fixed version(s) of whichever range actually contains `current` —
 * OSV lists one range per release branch (e.g. introduced 0 → fixed 3.10.2,
 * introduced 4.0.0 → fixed 4.17.21), and only the branch you're on says what
 * to upgrade *to*. An `introduced` of "0" means "from the beginning".
 */
function fixedInCurrentBranch(ranges: OsvRange[], current: [number, number, number]): string[] {
  const out: string[] = [];
  for (const range of ranges) {
    let introduced: [number, number, number] | null = [0, 0, 0];
    for (const event of range.events ?? []) {
      if (event.introduced !== undefined) introduced = event.introduced === "0" ? [0, 0, 0] : parseConcreteVersion(event.introduced);
      if (event.fixed === undefined) continue;
      const fixed = parseConcreteVersion(event.fixed);
      if (fixed && introduced && compareConcreteVersions(current, introduced) >= 0 && compareConcreteVersions(current, fixed) < 0) {
        out.push(event.fixed);
      }
    }
  }
  return out;
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
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ package: { name: packageName, ecosystem }, version }),
      signal: AbortSignal.timeout(OSV_TIMEOUT_MS),
    });
    if (!res.ok) return empty;

    const body = (await res.json()) as { vulns?: OsvVulnFull[] };
    const vulns = body.vulns ?? [];
    if (vulns.length === 0) {
      fixCache.set(cacheKey, empty);
      return empty;
    }

    const isCve = (id: string) => /^CVE-\d{4}-\d{4,}$/i.test(id);
    const cveIds = [
      ...new Set(vulns.flatMap((v) => [v.id, ...(v.aliases ?? [])]).filter(isCve).map((id) => id.toUpperCase())),
    ];
    const osvIds = [...new Set(vulns.map((v) => v.id).filter((id): id is string => typeof id === "string"))];

    // Every returned vuln must name a concrete fixed version for this
    // package for us to claim a single safe target version — if any one of
    // them doesn't, we cannot say the package is fully fixed at any version,
    // so the whole lookup reports fixedVersion: null.
    const current = parseConcreteVersion(version);
    const toParsed = (fs: string[]) =>
      fs
        .map((f) => ({ raw: f, parsed: parseConcreteVersion(f) }))
        .filter((f): f is { raw: string; parsed: [number, number, number] } => f.parsed !== null);

    let maxFixed: [number, number, number] | null = null;
    let maxFixedStr: string | null = null;
    for (const v of vulns) {
      const matchingRanges = (v.affected ?? [])
        .filter((a) => a.package?.name === packageName && a.package?.ecosystem === ecosystem)
        .flatMap((a) => a.ranges ?? [])
        .filter((r) => r.type === "SEMVER");

      const allFixed = toParsed(
        matchingRanges.flatMap((r) => r.events ?? []).map((e) => e.fixed).filter((f): f is string => typeof f === "string")
      );

      if (allFixed.length === 0) {
        // This vuln has no matching range with a concrete fixed version —
        // either still unpatched, or only a last_affected event. Bail out
        // entirely: we cannot promise a single version fixes everything.
        fixCache.set(cacheKey, { cveIds, osvIds, fixedVersion: null });
        return { cveIds, osvIds, fixedVersion: null };
      }

      // Prefer the fix on the branch the package is actually on — the lowest
      // version that resolves this vuln. Taking the highest fix across every
      // branch (what this used to do) turned a 3.10.0 → 3.10.2 patch into a
      // breaking 3.x → 4.x upgrade PR. When the current version can't be
      // placed in a range, keep the old conservative choice (highest fix).
      const inBranch = current ? toParsed(fixedInCurrentBranch(matchingRanges, current)) : [];
      const pick = inBranch.length > 0
        ? inBranch.reduce((lo, f) => (compareConcreteVersions(f.parsed, lo.parsed) < 0 ? f : lo))
        : allFixed.reduce((hi, f) => (compareConcreteVersions(f.parsed, hi.parsed) > 0 ? f : hi));

      if (maxFixed === null || compareConcreteVersions(pick.parsed, maxFixed) > 0) {
        maxFixed = pick.parsed;
        maxFixedStr = pick.raw;
      }
    }

    const result: OsvFixInfo = { cveIds, osvIds, fixedVersion: maxFixedStr };
    fixCache.set(cacheKey, result);
    return result;
  } catch {
    return empty;
  }
}

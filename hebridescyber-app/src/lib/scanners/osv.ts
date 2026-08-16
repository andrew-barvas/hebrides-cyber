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

// Keyed by "package@version". Many customers run the same jQuery version, so
// this avoids a redundant OSV round-trip per scan within one warm process —
// best-effort only, there's no persistence or eviction, since serverless
// instances are short-lived anyway and this is a cheap win, not a cache layer
// worth building infrastructure for.
const cache = new Map<string, string[]>();

/** Extracts any CVE ids already present in free text — the fallback when a
 *  live OSV lookup fails or returns nothing, since webapp.ts's static
 *  `reason` strings already name specific CVEs for several libraries. */
export function extractCveIdsFromText(text: string): string[] {
  const matches = text.match(/CVE-\d{4}-\d{4,}/gi) ?? [];
  return [...new Set(matches.map((m) => m.toUpperCase()))];
}

/**
 * Looks up known vulnerabilities for an npm package/version via OSV.dev.
 * Never throws — a failed or empty lookup returns [], the caller is expected
 * to fall back to extractCveIdsFromText on its own static reason text.
 */
export async function lookupNpmCveIds(packageName: string, version: string): Promise<string[]> {
  if (version === "unknown") return [];

  const cacheKey = `${packageName}@${version}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ package: { name: packageName, ecosystem: "npm" }, version }),
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

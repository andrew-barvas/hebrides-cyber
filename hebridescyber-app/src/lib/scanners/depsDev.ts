// Dependency licence lookup via deps.dev (https://deps.dev) — free, keyless,
// Google-run. The dependency inventory (dependencyManifest.ts) and the
// CycloneDX SBOM (sbomExport.ts) carry no licence data; deps.dev gives the
// per-package SPDX licence(s) that turn "what do we depend on" into "and under
// what licence", which is what a licence-compliance finding needs.
//
// Mirrors osv.ts's bulk path exactly: a const base URL, AbortSignal.timeout on
// every request, a bounded-concurrency worker pool, a module-level cache keyed
// `ecosystem:name@version`, one retry on a transient 5xx/429, and a never-throw
// `{ ok } | { error }` return. A failed lookup is reported as a failure (or
// simply omitted), NEVER as "no licence" / "compliant" — evidence discipline.
//
// deps.dev covers GO, RUBYGEMS, NPM, CARGO, MAVEN, PYPI, NUGET. It does NOT
// cover Packagist (PHP) or any ecosystem not in SYSTEM_FOR_ECOSYSTEM, so those
// packages are skipped rather than guessed.

import type { OsvEcosystem } from "./dependencyLockfiles";

const DEPS_DEV_API = "https://api.deps.dev/v3";
const DEPS_DEV_TIMEOUT_MS = 5_000;
const DEFAULT_CONCURRENCY = 10;

/** OSV ecosystem → deps.dev "system". Ecosystems deps.dev doesn't cover are absent. */
export const SYSTEM_FOR_ECOSYSTEM: Partial<Record<OsvEcosystem, string>> = {
  npm: "npm",
  PyPI: "pypi",
  Go: "go",
  Maven: "maven",
  RubyGems: "rubygems",
  "crates.io": "cargo",
  NuGet: "nuget",
  // Packagist (PHP) is deliberately omitted — deps.dev has no PHP system.
};

export type DepsDevQuery = { ecosystem: OsvEcosystem; name: string; version: string };

/** The one field this app reads from a deps.dev version record. */
type DepsDevVersion = { licenses?: unknown };

/** A package's SPDX licence expressions, or an error — never "no licence" on failure. */
export type LicenseLookup =
  | { ok: true; licenses: string[] }
  | { ok: false; error: string };

const cacheKeyOf = (q: DepsDevQuery) => `${q.ecosystem}:${q.name}@${q.version}`;

// Keyed `ecosystem:name@version`. Many scans share the same popular packages,
// and licences change rarely, so one lookup per package per warm process is
// plenty — best-effort, no persistence or eviction (same rationale as osv.ts).
const cache = new Map<string, LicenseLookup>();

/** deps.dev's version path. Maven coordinates use `group:artifact`, which must be URL-encoded whole. */
export function versionPath(system: string, name: string, version: string): string {
  return `${DEPS_DEV_API}/systems/${system}/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}`;
}

/** Pure: the SPDX ids from a deps.dev version record's `licenses` array (strings only, de-duplicated). */
export function licensesFromRecord(record: DepsDevVersion | null): string[] {
  const raw = record?.licenses;
  if (!Array.isArray(raw)) return [];
  return [...new Set(raw.filter((l): l is string => typeof l === "string" && l.length > 0))];
}

async function lookupOne(query: DepsDevQuery): Promise<LicenseLookup> {
  const cached = cache.get(cacheKeyOf(query));
  if (cached) return cached;

  const system = SYSTEM_FOR_ECOSYSTEM[query.ecosystem];
  if (!system) {
    // Not an error — deps.dev simply doesn't cover this ecosystem.
    const result: LicenseLookup = { ok: true, licenses: [] };
    cache.set(cacheKeyOf(query), result);
    return result;
  }

  const url = versionPath(system, query.name, query.version);
  let lastError = "";
  // One retry on a transient failure, same as osv.ts's postBatch.
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(DEPS_DEV_TIMEOUT_MS) });
      if (res.status === 404) {
        // The version isn't known to deps.dev — a definite "no licence data",
        // not a transient error. Cache it as an empty-but-ok result.
        const result: LicenseLookup = { ok: true, licenses: [] };
        cache.set(cacheKeyOf(query), result);
        return result;
      }
      if (!res.ok) {
        lastError = `deps.dev returned HTTP ${res.status}`;
        if (res.status >= 500 || res.status === 429) continue;
        return { ok: false, error: lastError };
      }
      const body = (await res.json()) as DepsDevVersion;
      const result: LicenseLookup = { ok: true, licenses: licensesFromRecord(body) };
      cache.set(cacheKeyOf(query), result);
      return result;
    } catch (err) {
      lastError = `deps.dev lookup failed: ${(err as Error).message}`;
    }
  }
  return { ok: false, error: lastError };
}

/**
 * Licences for many packages, looked up with bounded concurrency. Returns a
 * Map keyed `ecosystem:name@version` holding only the packages that resolved to
 * at least one licence — a failed or empty lookup contributes nothing (never a
 * false "unlicensed"). The `failed` count lets the caller note partial coverage.
 */
export async function lookupLicenses(
  queries: DepsDevQuery[],
  options: { concurrency?: number } = {}
): Promise<{ licenses: Map<string, string[]>; failed: number }> {
  const licenses = new Map<string, string[]>();
  // De-duplicate: the same package@version can appear in several files.
  const unique = [...new Map(queries.map((q) => [cacheKeyOf(q), q])).values()];
  let next = 0;
  let failed = 0;

  const worker = async () => {
    while (next < unique.length) {
      const query = unique[next++];
      const result = await lookupOne(query);
      if (!result.ok) {
        failed++;
        continue;
      }
      if (result.licenses.length > 0) licenses.set(cacheKeyOf(query), result.licenses);
    }
  };
  await Promise.all(Array.from({ length: Math.min(options.concurrency ?? DEFAULT_CONCURRENCY, Math.max(1, unique.length)) }, worker));
  return { licenses, failed };
}

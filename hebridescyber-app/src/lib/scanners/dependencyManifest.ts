// Real npm dependency manifest scanning — closes the gap between what the
// pricing/services pages claim ("dependency scan (npm, pip, composer)") and
// what previously existed: src/lib/scanners/webapp.ts only ever did
// client-side JS library *detection* (HTML/global pattern matching), never a
// server-side manifest scan.
//
// v1 IS DELIBERATELY SCOPED TO npm/package.json — matching exactly what
// src/lib/scanners/osv.ts already supports (lookupCveIds's ecosystem param).
// pip and composer are a real gap this module does not close; the marketing
// copy overclaims until those ecosystems get their own module. Not this
// file's problem to fix — see the DO NOT EDIT list for marketing pages.
//
// NO LOCKFILE. This reads package.json's declared dependency *ranges*, not
// package-lock.json's exact resolved versions — there is no lockfile fetch
// here. minVersionFromRange() reduces a range like "^4.17.11" down to the
// lowest version it could resolve to that OSV.dev can be queried against.
// That is a real, disclosed approximation (called out in the Finding detail
// and in remediationText.ts's dependencyVulnerableRemediation): the actual
// installed version could be newer and already patched. What it is NOT is a
// guess at whether a vulnerability exists — every finding here still comes
// from a real OSV.dev advisory matched against a real version string, never
// fabricated. Ranges that can't be reduced to a concrete version with
// confidence (wildcards, "latest", git/workspace/link/file specifiers, OR
// alternatives) are skipped rather than guessed at.
//
// Requires a connected repo (sql/migrations/009_repo_connections.sql,
// written via src/pages/api/account/connect-repo.ts). No repo, or no
// package.json at the repo root, is a clean "not_applicable" result — never
// an error finding. Never throws, matching every other scanner module's
// contract.
//
// GitHub access resolves through src/lib/githubApp.ts's resolveGithubAuth():
// a GitHub App installation token if the customer has installed the App on
// this repo, else the shared GITHUB_PAT (the original, sole path — see that
// module's header for why a shared PAT across every customer needed
// narrowing). `owner/repo` format, plain fetch against api.github.com.

import type { Finding } from "./index";
import { lookupCveIds } from "./osv";
import { dependencyVulnerableRemediation } from "./remediationText";
import { resolveGithubAuth } from "../githubApp";

const githubApi = "https://api.github.com";
const GITHUB_API_TIMEOUT_MS = 10_000;

// A project with 200 dependencies must not produce 200 rows. Same capping
// pattern as subdomains.ts's MAX_HOST_FINDINGS / secretScan.ts's MAX_FINDINGS:
// list the first N individually, roll the rest into one summary finding.
const MAX_FINDINGS = 30;

// Ceiling on OSV.dev round-trips per scan. Dependencies beyond this are
// still counted in the manifest total but not individually queried — called
// out in the result's note, never silently dropped.
const MAX_PACKAGES_QUERIED = 150;

// Parallel OSV.dev lookups. OSV.dev is keyless and generally tolerant, but
// there's no reason to fire 150 requests at once.
const QUERY_CONCURRENCY = 10;

function ghHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

export type DependencyManifestResult =
  | { status: "completed"; repo: string; dependenciesDeclared: number; dependenciesChecked: number; findings: Finding[]; note?: string }
  | { status: "not_applicable"; repo: string; findings: []; note: string }
  | { status: "not_configured"; repo: string; findings: []; note: string };

export type DependencyManifestOptions = {
  /** null/empty when the scan owner has no repo_connections row. */
  githubRepo: string | null | undefined;
  /** Defaults to src/lib/githubApp.ts's resolveGithubAuth() result (App token or GITHUB_PAT). Override only for tests/local verification. */
  githubToken?: string;
};

type PackageJsonShape = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};

/**
 * Reduces a package.json semver range down to the lowest version it could
 * resolve to. Deliberately conservative: anything that isn't confidently a
 * single dotted version after stripping a leading range operator returns
 * null (skip), rather than guessing. That excludes "*", "latest", "next",
 * OR-ranges ("1.x || 2.x"), and non-registry specifiers (git/file/link/
 * workspace URLs) — none of which OSV.dev could meaningfully be queried with
 * anyway.
 */
export function minVersionFromRange(range: string): string | null {
  const trimmed = (range ?? "").trim();
  if (!trimmed) return null;
  if (/^(git|git\+|file:|link:|workspace:|https?:)/i.test(trimmed)) return null;
  if (/[|*x]/i.test(trimmed) || /^(latest|next)$/i.test(trimmed)) return null;

  const cleaned = trimmed.replace(/^[\^~>=<\s]+/, "");
  const match = cleaned.match(/^\d+\.\d+\.\d+/);
  return match ? match[0] : null;
}

async function fetchPackageJson(githubRepo: string, token: string): Promise<PackageJsonShape | null> {
  try {
    const res = await fetch(`${githubApi}/repos/${githubRepo}/contents/package.json`, {
      headers: ghHeaders(token),
      signal: AbortSignal.timeout(GITHUB_API_TIMEOUT_MS),
    });
    if (!res.ok) return null;

    const body = (await res.json()) as { content?: string; encoding?: string };
    if (!body.content) return null;

    const decoded = Buffer.from(body.content, (body.encoding as BufferEncoding) ?? "base64").toString("utf-8");
    const parsed: unknown = JSON.parse(decoded);
    if (!parsed || typeof parsed !== "object") return null;
    return parsed as PackageJsonShape;
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

/**
 * Exported for local verification without a GitHub token/repo: it's the half
 * of this module that must be provable against real OSV.dev data alone.
 */
export async function buildDependencyFindings(
  pkg: PackageJsonShape
): Promise<{ findings: Finding[]; dependenciesDeclared: number; dependenciesChecked: number; note?: string }> {
  const deps: Record<string, string> = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
  const names = Object.keys(deps);

  const queryable = names
    .map((name) => ({ name, declaredRange: deps[name], version: minVersionFromRange(deps[name]) }))
    .filter((d): d is { name: string; declaredRange: string; version: string } => d.version !== null)
    .slice(0, MAX_PACKAGES_QUERIED);

  const checked = await mapWithConcurrency(queryable, QUERY_CONCURRENCY, async (d) => ({
    ...d,
    cveIds: await lookupCveIds("npm", d.name, d.version),
  }));

  // Deterministic order (alphabetical by name) so the MAX_FINDINGS cap and
  // the New/Fixed diff (checkId-keyed) behave consistently run to run,
  // matching subdomains.ts's rationale for sorting before capping.
  const vulnerable = checked.filter((c) => c.cveIds.length > 0).sort((a, b) => a.name.localeCompare(b.name));

  const findings: Finding[] = [];
  const listed = vulnerable.slice(0, MAX_FINDINGS);
  for (const v of listed) {
    findings.push({
      checkId: `dependency-manifest.npm:${v.name}`,
      severity: "medium",
      title: `Vulnerable dependency: ${v.name}@${v.version}`,
      detail: `OSV.dev reports ${v.cveIds.length} known CVE${v.cveIds.length === 1 ? "" : "s"} (${v.cveIds.join(", ")}) affecting ${v.name} at version ${v.version}, the minimum version resolvable from the range declared in package.json ("${v.declaredRange}"). This is a manifest-based check, not a lockfile-exact match — the actual installed version may differ.`,
      remediation: dependencyVulnerableRemediation(v.name),
      cveIds: v.cveIds,
    });
  }

  const remaining = vulnerable.length - listed.length;
  if (remaining > 0) {
    findings.push({
      checkId: "dependency-manifest.additional-vulnerable",
      severity: "info",
      title: `${remaining} further vulnerable npm dependenc${remaining === 1 ? "y" : "ies"} not listed individually`,
      detail: `${vulnerable.length} vulnerable dependencies were found in total out of ${names.length} declared in package.json; the first ${MAX_FINDINGS} are listed above. Additional: ${vulnerable.slice(MAX_FINDINGS, MAX_FINDINGS + 10).map((v) => v.name).join(", ")}${remaining > 10 ? ` (+${remaining - 10} more)` : ""}.`,
    });
  }

  const notes: string[] = [];
  const skipped = names.length - queryable.length;
  if (names.length > MAX_PACKAGES_QUERIED) {
    notes.push(`Only the first ${MAX_PACKAGES_QUERIED} of ${names.length} declared dependencies were queried against OSV.dev.`);
  } else if (skipped > 0) {
    notes.push(`${skipped} of ${names.length} declared dependencies had a version range that couldn't be reduced to a concrete version (wildcards, tags, or git/workspace/file references) and were not queried.`);
  }

  return {
    findings,
    dependenciesDeclared: names.length,
    dependenciesChecked: queryable.length,
    ...(notes.length ? { note: notes.join(" ") } : {}),
  };
}

/**
 * Scans the connected repo's package.json dependencies + devDependencies
 * against OSV.dev. Never throws.
 */
export async function scanDependencyManifest(options: DependencyManifestOptions): Promise<DependencyManifestResult> {
  const githubRepo = options.githubRepo || null;

  if (!githubRepo) {
    return { status: "not_applicable", repo: "", findings: [], note: "no repository connected — see /account to connect one." };
  }
  if (!/^[\w.-]+\/[\w.-]+$/.test(githubRepo)) {
    return { status: "not_applicable", repo: githubRepo, findings: [], note: "connected githubRepo is not a valid 'owner/repo' — reconnect via /account." };
  }
  const token = options.githubToken ?? (await resolveGithubAuth(githubRepo)).token;
  if (!token) {
    return { status: "not_configured", repo: githubRepo, findings: [], note: "No GitHub access configured (neither a GitHub App installation nor GITHUB_PAT) — skipping dependency manifest scan. See .env.example." };
  }

  try {
    const pkg = await fetchPackageJson(githubRepo, token);
    if (!pkg) {
      return { status: "not_applicable", repo: githubRepo, findings: [], note: "package.json not found or unreadable at the repository root — nothing to scan." };
    }

    const { findings, dependenciesDeclared, dependenciesChecked, note } = await buildDependencyFindings(pkg);
    return { status: "completed", repo: githubRepo, dependenciesDeclared, dependenciesChecked, findings, ...(note ? { note } : {}) };
  } catch {
    // Backstop: this function's contract is that it never throws.
    return { status: "not_applicable", repo: githubRepo, findings: [], note: "dependency manifest scan could not complete — treating as not applicable rather than surfacing an error finding." };
  }
}

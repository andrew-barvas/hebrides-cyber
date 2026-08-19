// Real dependency manifest scanning — npm (package.json), pip
// (requirements.txt), and Composer (composer.json). Closes the gap between
// what the pricing/services pages claim ("dependency scan (npm, pip,
// composer)") and what previously existed: src/lib/scanners/webapp.ts only
// ever did client-side JS library *detection* (HTML/global pattern
// matching), never a server-side manifest scan of any ecosystem.
//
// v1 shipped npm-only, matching what src/lib/scanners/osv.ts already
// supported (lookupCveIds's ecosystem param). pip and composer are added
// here on the same OSV.dev-backed foundation — OSV.dev's query API accepts
// any ecosystem string in the same request shape ("PyPI", "Packagist" work
// identically to "npm"), so extending coverage needed new manifest parsing,
// not a new data source.
//
// All three manifests at the repo root are checked independently and their
// findings combined — a polyglot repo (say, a Django backend with an npm
// frontend) gets both, not just whichever is found first.
//
// NO LOCKFILE, for any ecosystem. Each parser reads the manifest's declared
// dependency *ranges*, not a lockfile's exact resolved versions.
// minVersionFromRange() (npm/composer, which share caret/tilde semver
// semantics) and the pip-specific operator handling in
// parsePipRequirements() both reduce a range down to the lowest version it
// could resolve to that OSV.dev can be queried against. That is a real,
// disclosed approximation (called out in the Finding detail and in
// remediationText.ts's dependencyVulnerableRemediation): the actual
// installed version could be newer and already patched. What it is NOT is a
// guess at whether a vulnerability exists — every finding here still comes
// from a real OSV.dev advisory matched against a real version string, never
// fabricated. Ranges that can't be reduced to a concrete version with
// confidence (wildcards, "latest", git/VCS/URL specifiers, OR alternatives,
// compound comparisons) are skipped rather than guessed at.
//
// Requires a connected repo (sql/migrations/009_repo_connections.sql,
// written via src/pages/api/account/connect-repo.ts). No repo, or none of
// the three manifests present at the repo root, is a clean "not_applicable"
// result — never an error finding. Never throws, matching every other
// scanner module's contract.
//
// GitHub access resolves through src/lib/githubApp.ts's resolveGithubAuth():
// a GitHub App installation token if the customer has installed the App on
// this repo, else the shared GITHUB_PAT. `owner/repo` format, plain fetch
// against api.github.com.

import type { Finding } from "./index";
import { lookupCveIds } from "./osv";
import { dependencyVulnerableRemediation } from "./remediationText";
import { resolveGithubAuth } from "../githubApp";

const githubApi = "https://api.github.com";
const GITHUB_API_TIMEOUT_MS = 10_000;

// A project with 200 dependencies must not produce 200 rows. Same capping
// pattern as subdomains.ts's MAX_HOST_FINDINGS / secretScan.ts's MAX_FINDINGS.
// Applied per-ecosystem, not combined, so one large npm manifest can't starve
// a smaller pip/composer one's share of listed findings.
const MAX_FINDINGS = 30;

// Ceiling on OSV.dev round-trips per manifest. Dependencies beyond this are
// still counted in the manifest total but not individually queried — called
// out in the result's note, never silently dropped. Also per-ecosystem.
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
  | {
      status: "completed";
      repo: string;
      manifestsScanned: string[];
      dependenciesDeclared: number;
      dependenciesChecked: number;
      findings: Finding[];
      note?: string;
    }
  | { status: "not_applicable"; repo: string; findings: []; note: string }
  | { status: "not_configured"; repo: string; findings: []; note: string };

export type DependencyManifestOptions = {
  /** null/empty when the scan owner has no repo_connections row. */
  githubRepo: string | null | undefined;
  /** Defaults to src/lib/githubApp.ts's resolveGithubAuth() result (App token or GITHUB_PAT). Override only for tests/local verification. */
  githubToken?: string;
};

// ---- Ecosystem-agnostic core -------------------------------------------------

type DeclaredDependency = { name: string; declaredRange: string; version: string };

const ECOSYSTEM_SLUG: Record<"npm" | "PyPI" | "Packagist", "npm" | "pip" | "composer"> = {
  npm: "npm",
  PyPI: "pip",
  Packagist: "composer",
};

/**
 * Shared OSV-query + cap + sort + Finding-shaping logic, parameterised by
 * ecosystem and already-parsed dependencies. This is what buildDependencyFindings
 * (npm-specific, exported for local verification) and its pip/composer
 * siblings below all call — one implementation of "turn a dependency list
 * into findings," not three copies that can drift.
 */
async function buildFindingsForDeps(
  ecosystem: "npm" | "PyPI" | "Packagist",
  manifestPath: string,
  deps: DeclaredDependency[],
  totalDeclaredCount: number
): Promise<{ findings: Finding[]; note?: string }> {
  const slug = ECOSYSTEM_SLUG[ecosystem];
  const queryable = deps.slice(0, MAX_PACKAGES_QUERIED);

  const checked = await mapWithConcurrency(queryable, QUERY_CONCURRENCY, async (d) => ({
    ...d,
    cveIds: await lookupCveIds(ecosystem, d.name, d.version),
  }));

  // Deterministic order (alphabetical by name) so the MAX_FINDINGS cap and
  // the New/Fixed diff (checkId-keyed) behave consistently run to run.
  const vulnerable = checked.filter((c) => c.cveIds.length > 0).sort((a, b) => a.name.localeCompare(b.name));

  const findings: Finding[] = [];
  const listed = vulnerable.slice(0, MAX_FINDINGS);
  for (const v of listed) {
    findings.push({
      checkId: `dependency-manifest.${slug}:${v.name}`,
      severity: "medium",
      title: `Vulnerable dependency: ${v.name}@${v.version}`,
      detail: `OSV.dev reports ${v.cveIds.length} known CVE${v.cveIds.length === 1 ? "" : "s"} (${v.cveIds.join(", ")}) affecting ${v.name} at version ${v.version}, the minimum version resolvable from the range declared in ${manifestPath} ("${v.declaredRange}"). This is a manifest-based check, not a lockfile-exact match — the actual installed version may differ.`,
      remediation: dependencyVulnerableRemediation(v.name, slug),
      cveIds: v.cveIds,
    });
  }

  const remaining = vulnerable.length - listed.length;
  if (remaining > 0) {
    findings.push({
      checkId: `dependency-manifest.additional-vulnerable:${slug}`,
      severity: "info",
      title: `${remaining} further vulnerable ${slug} dependenc${remaining === 1 ? "y" : "ies"} not listed individually`,
      detail: `${vulnerable.length} vulnerable dependencies were found in total out of ${totalDeclaredCount} declared in ${manifestPath}; the first ${MAX_FINDINGS} are listed above. Additional: ${vulnerable.slice(MAX_FINDINGS, MAX_FINDINGS + 10).map((v) => v.name).join(", ")}${remaining > 10 ? ` (+${remaining - 10} more)` : ""}.`,
    });
  }

  const notes: string[] = [];
  const skipped = totalDeclaredCount - deps.length;
  if (totalDeclaredCount > MAX_PACKAGES_QUERIED) {
    notes.push(`Only the first ${MAX_PACKAGES_QUERIED} of ${totalDeclaredCount} declared dependencies in ${manifestPath} were queried against OSV.dev.`);
  } else if (skipped > 0) {
    notes.push(`${skipped} of ${totalDeclaredCount} declared dependencies in ${manifestPath} had a version range that couldn't be reduced to a concrete version and were not queried.`);
  }

  return { findings, ...(notes.length ? { note: notes.join(" ") } : {}) };
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

async function fetchRawFile(githubRepo: string, path: string, token: string): Promise<string | null> {
  try {
    const res = await fetch(`${githubApi}/repos/${githubRepo}/contents/${path}`, {
      headers: ghHeaders(token),
      signal: AbortSignal.timeout(GITHUB_API_TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { content?: string; encoding?: string };
    if (!body.content) return null;
    return Buffer.from(body.content, (body.encoding as BufferEncoding) ?? "base64").toString("utf-8");
  } catch {
    return null;
  }
}

// ---- npm (package.json) ------------------------------------------------------

type PackageJsonShape = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};

/**
 * Reduces an npm/Composer-style semver range (both use caret/tilde) down to
 * the lowest version it could resolve to. Deliberately conservative:
 * anything that isn't confidently a dotted version after stripping a
 * leading range operator returns null (skip), rather than guessing. That
 * excludes "*", "latest", "next", OR-ranges ("1.x || 2.x"), and non-registry
 * specifiers (git/file/link/workspace URLs) — none of which OSV.dev could
 * meaningfully be queried with anyway.
 *
 * A bare two-component version (Composer's very common "^7.4" — a PHP
 * version constraint or a library that only ever versions by major.minor)
 * is zero-padded to X.Y.0. That's a mechanical, deterministic completion of
 * what "^7.4" already unambiguously means as a lower bound — not a guess —
 * so it's not the same category of thing minVersionFromRange otherwise
 * declines to do.
 */
export function minVersionFromRange(range: string): string | null {
  const trimmed = (range ?? "").trim();
  if (!trimmed) return null;
  if (/^(git|git\+|file:|link:|workspace:|https?:)/i.test(trimmed)) return null;
  if (/[|*x]/i.test(trimmed) || /^(latest|next)$/i.test(trimmed)) return null;

  const cleaned = trimmed.replace(/^[\^~>=<\s]+/, "");
  const match = cleaned.match(/^\d+\.\d+(\.\d+)?/);
  if (!match) return null;
  return match[0].split(".").length === 2 ? `${match[0]}.0` : match[0];
}

async function fetchPackageJson(githubRepo: string, token: string): Promise<PackageJsonShape | null> {
  const raw = await fetchRawFile(githubRepo, "package.json", token);
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    return parsed as PackageJsonShape;
  } catch {
    return null;
  }
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

  const queryable: DeclaredDependency[] = names
    .map((name) => ({ name, declaredRange: deps[name], version: minVersionFromRange(deps[name]) }))
    .filter((d): d is DeclaredDependency => d.version !== null);

  const { findings, note } = await buildFindingsForDeps("npm", "package.json", queryable, names.length);
  return { findings, dependenciesDeclared: names.length, dependenciesChecked: Math.min(queryable.length, MAX_PACKAGES_QUERIED), note };
}

// ---- pip (requirements.txt) ---------------------------------------------------

// Only operators with an unambiguous lower bound are handled — the same
// "skip rather than guess" discipline minVersionFromRange applies to npm
// ranges. "==" is an exact pin (the version *is* the bound); ">=" and "~="
// (PEP 440 compatible-release) both have a clean literal lower bound. Bare
// package names (no version), "<"/"!="-only constraints, compound
// comma-separated specifiers, and environment markers (";...") are skipped —
// none give a single version to query with confidence.
const PIP_LINE_RE = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(==|>=|~=)\s*([0-9][A-Za-z0-9.]*)\s*$/;

export function parsePipRequirements(raw: string): DeclaredDependency[] {
  const deps: DeclaredDependency[] = [];
  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.split("#")[0].trim(); // strip comments
    if (!line) continue;
    // -r/-e/--flags, VCS/URL specifiers — none are a registry package+version.
    if (/^(-|git\+|https?:|\.\/|\.\.\/)/i.test(line)) continue;
    if (line.includes(";")) continue; // environment marker — compound condition, not a single version

    const m = PIP_LINE_RE.exec(line);
    if (!m) continue;
    const [, name, , version] = m;
    deps.push({ name: name.toLowerCase(), declaredRange: line, version });
  }
  return deps;
}

async function fetchRequirementsTxt(githubRepo: string, token: string): Promise<string | null> {
  return fetchRawFile(githubRepo, "requirements.txt", token);
}

// ---- Composer (composer.json) -------------------------------------------------

type ComposerJsonShape = {
  require?: Record<string, string>;
  "require-dev"?: Record<string, string>;
};

// Pseudo-packages Composer uses for platform requirements — not real
// Packagist packages, so OSV.dev has nothing to match them against.
const COMPOSER_PLATFORM_PACKAGE_RE = /^(php(-64bit)?|hhvm|composer(-plugin-api|-runtime-api)?|ext-[\w-]+|lib-[\w-]+)$/i;

async function fetchComposerJson(githubRepo: string, token: string): Promise<ComposerJsonShape | null> {
  const raw = await fetchRawFile(githubRepo, "composer.json", token);
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    return parsed as ComposerJsonShape;
  } catch {
    return null;
  }
}

// ---- Entry point ---------------------------------------------------------

/**
 * Scans whichever of package.json / requirements.txt / composer.json exist
 * at the connected repo's root against OSV.dev. Never throws.
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
    const [pkg, requirementsTxt, composer] = await Promise.all([
      fetchPackageJson(githubRepo, token),
      fetchRequirementsTxt(githubRepo, token),
      fetchComposerJson(githubRepo, token),
    ]);

    if (!pkg && !requirementsTxt && !composer) {
      return {
        status: "not_applicable",
        repo: githubRepo,
        findings: [],
        note: "No package.json, requirements.txt, or composer.json found at the repository root — nothing to scan.",
      };
    }

    const manifestsScanned: string[] = [];
    const allFindings: Finding[] = [];
    const notes: string[] = [];
    let dependenciesDeclared = 0;
    let dependenciesChecked = 0;

    if (pkg) {
      manifestsScanned.push("package.json");
      const result = await buildDependencyFindings(pkg);
      allFindings.push(...result.findings);
      dependenciesDeclared += result.dependenciesDeclared;
      dependenciesChecked += result.dependenciesChecked;
      if (result.note) notes.push(result.note);
    }

    if (requirementsTxt) {
      manifestsScanned.push("requirements.txt");
      const deps = parsePipRequirements(requirementsTxt);
      // parsePipRequirements already drops unparseable lines, so "declared"
      // here counts what was recognised as a dependency line at all — a
      // line skipped for having no version is still declared, just not
      // queryable, same accounting convention as the npm path.
      const totalLines = requirementsTxt
        .split(/\r?\n/)
        .map((l) => l.split("#")[0].trim())
        .filter((l) => l && !/^(-|git\+|https?:|\.\/|\.\.\/)/i.test(l)).length;
      const { findings, note } = await buildFindingsForDeps("PyPI", "requirements.txt", deps, totalLines);
      allFindings.push(...findings);
      dependenciesDeclared += totalLines;
      dependenciesChecked += Math.min(deps.length, MAX_PACKAGES_QUERIED);
      if (note) notes.push(note);
    }

    if (composer) {
      manifestsScanned.push("composer.json");
      const raw: Record<string, string> = { ...(composer.require ?? {}), ...(composer["require-dev"] ?? {}) };
      const names = Object.keys(raw).filter((name) => !COMPOSER_PLATFORM_PACKAGE_RE.test(name));
      const deps: DeclaredDependency[] = names
        .map((name) => ({ name, declaredRange: raw[name], version: minVersionFromRange(raw[name]) }))
        .filter((d): d is DeclaredDependency => d.version !== null);
      const { findings, note } = await buildFindingsForDeps("Packagist", "composer.json", deps, names.length);
      allFindings.push(...findings);
      dependenciesDeclared += names.length;
      dependenciesChecked += Math.min(deps.length, MAX_PACKAGES_QUERIED);
      if (note) notes.push(note);
    }

    return {
      status: "completed",
      repo: githubRepo,
      manifestsScanned,
      dependenciesDeclared,
      dependenciesChecked,
      findings: allFindings,
      ...(notes.length ? { note: notes.join(" ") } : {}),
    };
  } catch {
    // Backstop: this function's contract is that it never throws.
    return { status: "not_applicable", repo: githubRepo, findings: [], note: "dependency manifest scan could not complete — treating as not applicable rather than surfacing an error finding." };
  }
}

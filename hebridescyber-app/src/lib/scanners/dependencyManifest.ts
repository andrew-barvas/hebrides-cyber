// Dependency scanning for a connected GitHub repo — the open-source half of
// what Snyk sells: every package the project installs, transitive ones
// included, checked against OSV.dev.
//
// LOCKFILE FIRST. For each ecosystem, a lockfile at the repo root is
// preferred (package-lock.json / npm-shrinkwrap.json / pnpm-lock.yaml /
// yarn.lock, poetry.lock / Pipfile.lock, composer.lock, go.sum, Gemfile.lock,
// Cargo.lock, packages.lock.json, gradle.lockfile — parsers in
// dependencyLockfiles.ts). A lockfile gives the exact installed version of
// every package and, for most formats, the dependency graph, so a finding
// can say "transitive, introduced via a > b > c". Most real vulnerabilities
// live in transitive dependencies, which a manifest never lists.
//
// MANIFEST FALLBACK. With no (readable) lockfile for an ecosystem, the old
// manifest-range check still runs for package.json, requirements.txt,
// composer.json, go.mod and pom.xml: each declared range reduced to the
// lowest version it allows (minVersionFromRange / the pip operator rules).
// That's a disclosed approximation — the installed version may be newer —
// and every such finding says so. Ranges that can't be reduced to a
// concrete version (wildcards, git/URL specifiers, OR ranges) are skipped
// rather than guessed at.
//
// OSV.dev: one POST /v1/querybatch for up to 1000 packages (≤ 2000 per repo),
// then GET /v1/vulns/{id} per advisory for aliases (CVE ids), severity and
// fixed versions (osv.ts). A failed batch makes the whole result "error" —
// never "no vulnerabilities" — so finding_lifecycle doesn't mark anything
// fixed on the strength of a lookup that didn't happen. A failed advisory
// *detail* fetch still reports the package (the batch said it's affected),
// just with less detail.
//
// The result also carries the full package inventory (not just vulnerable
// packages), which src/lib/sbomExport.ts turns into a CycloneDX SBOM.
//
// Requires a connected repo (sql/migrations/009_repo_connections.sql). No
// repo, or no supported file at the repo root, is a clean "not_applicable".
// Never throws. GitHub access resolves through githubApp.ts's
// resolveGithubAuth() (App installation token, else GITHUB_PAT).

import type { Finding } from "./index";
import {
  fetchOsvVulnDetails,
  fixedVersionFromVulns,
  osvCvss,
  osvSeverity,
  queryOsvBatch,
  cveIdsOf,
  type OsvVulnDetail,
} from "./osv";
import { dependencyVulnerableRemediation, type DependencyEcosystemSlug } from "./remediationText";
import { LOCKFILES, packageKey, type LockfilePackage, type OsvEcosystem } from "./dependencyLockfiles";
import { resolveGithubAuth } from "../githubApp";
import { assessTyposquatCandidates, buildTyposquatFinding, findTyposquatCandidates } from "./typosquatRisk";

const githubApi = "https://api.github.com";
const GITHUB_API_TIMEOUT_MS = 15_000;

// A project with 200 vulnerable dependencies must not produce 200 rows.
// Applied per ecosystem, so one large npm tree can't starve a smaller
// pip/composer one's share of listed findings.
const MAX_FINDINGS = 30;

/** Ceiling on packages queried (and kept in the inventory) per repo. Beyond it the note says how many were left out. */
export const MAX_PACKAGES_QUERIED = 2000;

/** Advisory detail fetches per scan; ids beyond it are still reported, without detail. */
const MAX_VULN_DETAILS = 500;

// Parallel GET /v1/vulns/{id} requests.
const QUERY_CONCURRENCY = 10;

// Lockfiles of big projects run to several MB; the Contents API's JSON form
// stops returning content past 1 MB, which is why files are read raw.
const MAX_FILE_BYTES = 10 * 1024 * 1024;

function ghHeaders(token: string, raw = false): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    Accept: raw ? "application/vnd.github.raw+json" : "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

// ---- Result + inventory types ------------------------------------------------

export type DependencyInventoryFile = {
  file: string;
  ecosystem: OsvEcosystem;
  /** "lockfile": exact installed versions; "manifest": lowest version a declared range allows. */
  kind: "lockfile" | "manifest";
  /** The file records which package depends on which. */
  graph: boolean;
};

export type DependencyInventoryPackage = {
  ecosystem: OsvEcosystem;
  name: string;
  version: string;
  /** Declared by the project itself (true), pulled in by another package (false), unknown (null). */
  direct: boolean | null;
  /** "required" at runtime, "optional" for development-only or optional packages; absent when unknown. */
  scope?: "required" | "optional";
  /** Index into DependencyInventory.files. */
  fileIndex: number;
  /** Indices into DependencyInventory.packages, where the file records the graph. */
  dependsOn?: number[];
  /** OSV.dev advisory ids affecting this exact version. */
  vulnIds?: string[];
  /** The version OSV.dev names as fixing all of vulnIds, when it names one. */
  fixedVersion?: string;
};

export type DependencyAdvisory = {
  id: string;
  cveIds: string[];
  severity?: "critical" | "high" | "medium" | "low";
  cvssVector?: string;
  cvssScore?: number;
  summary?: string;
};

/** Every package found, stored with the scan so an SBOM can be produced later. Bounded by MAX_PACKAGES_QUERIED. */
export type DependencyInventory = {
  schemaVersion: 1;
  files: DependencyInventoryFile[];
  packages: DependencyInventoryPackage[];
  /** Packages found before the MAX_PACKAGES_QUERIED cap. */
  totalPackages: number;
  truncated: boolean;
  /** "failed" means vulnIds are absent because OSV.dev couldn't be asked — not because there are none. */
  vulnerabilityLookup: "completed" | "failed";
  advisories: DependencyAdvisory[];
};

export type DependencyManifestResult =
  | {
      status: "completed";
      repo: string;
      /** Every file read: lockfiles and manifests. */
      manifestsScanned: string[];
      lockfilesScanned?: string[];
      dependenciesDeclared: number;
      dependenciesChecked: number;
      findings: Finding[];
      inventory?: DependencyInventory;
      note?: string;
    }
  | { status: "error"; repo: string; findings: []; note: string; inventory?: DependencyInventory }
  | { status: "not_applicable"; repo: string; findings: []; note: string }
  | { status: "not_configured"; repo: string; findings: []; note: string };

export type DependencyManifestOptions = {
  /** null/empty when the scan owner has no repo_connections row. */
  githubRepo: string | null | undefined;
  /** Defaults to src/lib/githubApp.ts's resolveGithubAuth() result (App token or GITHUB_PAT). Override only for tests/local verification. */
  githubToken?: string;
};

// ---- Ecosystems ------------------------------------------------------------

/** checkId slug per OSV ecosystem: `dependency-manifest.<slug>:<name>`. The first five predate lockfile support and must not change. */
export const ECOSYSTEM_SLUG: Record<OsvEcosystem, DependencyEcosystemSlug> = {
  npm: "npm",
  PyPI: "pip",
  Packagist: "composer",
  Go: "go",
  Maven: "maven",
  RubyGems: "ruby",
  "crates.io": "cargo",
  NuGet: "nuget",
};

const ECOSYSTEM_ORDER: OsvEcosystem[] = ["npm", "PyPI", "Packagist", "Go", "Maven", "RubyGems", "crates.io", "NuGet"];

/** The manifest each ecosystem falls back to when it has no lockfile. */
const MANIFEST_FALLBACK: Partial<Record<OsvEcosystem, string>> = {
  npm: "package.json",
  PyPI: "requirements.txt",
  Packagist: "composer.json",
  Go: "go.mod",
  Maven: "pom.xml",
};

/** Every root file this scan may read: lockfiles, fallback manifests, and companions (pyproject.toml tells direct from transitive for poetry.lock). */
export const CANDIDATE_FILES: string[] = [...new Set([...LOCKFILES.map((l) => l.file), ...Object.values(MANIFEST_FALLBACK), "pyproject.toml"])];

/** One package to check, from either a lockfile or a manifest. */
export type ScannedPackage = {
  ecosystem: OsvEcosystem;
  name: string;
  version: string;
  direct: boolean | null;
  dev: boolean | null;
  optional?: boolean;
  introducedVia?: string[];
  dependsOn?: string[];
  file: string;
  /** true: lockfile-exact; false: lowest version allowed by a manifest range. */
  exact: boolean;
  declaredRange?: string;
};

type DeclaredDependency = { name: string; declaredRange: string; version: string };

// ---- Manifest parsers (fallback path) --------------------------------------

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
 * A bare two-component version (Composer's very common "^7.4") is
 * zero-padded to X.Y.0 — a mechanical completion of what "^7.4" already
 * unambiguously means as a lower bound, not a guess.
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

function npmManifestPackages(pkg: PackageJsonShape): { packages: ScannedPackage[]; declared: number } {
  const entries: Array<[string, string, boolean]> = [
    ...Object.entries(pkg.dependencies ?? {}).map(([n, r]) => [n, r, false] as [string, string, boolean]),
    ...Object.entries(pkg.devDependencies ?? {}).map(([n, r]) => [n, r, true] as [string, string, boolean]),
  ];
  const seen = new Set<string>();
  const packages: ScannedPackage[] = [];
  for (const [name, range, dev] of entries) {
    if (seen.has(name)) continue;
    seen.add(name);
    const version = typeof range === "string" ? minVersionFromRange(range) : null;
    if (version) packages.push({ ecosystem: "npm", name, version, direct: true, dev, file: "package.json", exact: false, declaredRange: range });
  }
  return { packages, declared: seen.size };
}

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

// Pseudo-packages Composer uses for platform requirements — not real
// Packagist packages, so OSV.dev has nothing to match them against.
const COMPOSER_PLATFORM_PACKAGE_RE = /^(php(-64bit)?|hhvm|composer(-plugin-api|-runtime-api)?|ext-[\w-]+|lib-[\w-]+)$/i;

// go.mod's `require` block pins exact versions (no ranges/carets — Go
// modules don't have that concept), so no range reduction is needed. Matches
// both the block form and the single-line `require x v1.2.3` form; `//
// indirect` dependencies are kept. OSV.dev's Go ecosystem expects versions
// without the leading "v". A pre-release/build suffix makes the line fail to
// match rather than being silently stripped down to "1.2.3", which would
// query a different version than the one declared.
const GO_REQUIRE_LINE_RE = /^(\S+)\s+v(\d+\.\d+\.\d+)(?:\s*\/\/.*)?$/;

export function parseGoModRequire(raw: string): DeclaredDependency[] {
  const deps: DeclaredDependency[] = [];
  const lines = raw.split(/\r?\n/);
  let inBlock = false;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;

    if (line === "require (") {
      inBlock = true;
      continue;
    }
    if (inBlock && line === ")") {
      inBlock = false;
      continue;
    }

    const candidate = inBlock ? line : line.replace(/^require\s+/, "");
    if (!inBlock && candidate === line) continue; // not a require line at all outside a block

    const m = GO_REQUIRE_LINE_RE.exec(candidate);
    if (!m) continue;
    deps.push({ name: m[1], declaredRange: candidate, version: m[2] });
  }
  return deps;
}

// No XML parser dependency — a targeted regex extraction. Only <dependency>
// blocks directly inside <dependencies> (not <dependencyManagement>, whose
// entries aren't necessarily all used). `${property}` versions are resolved
// against the <properties> block; anything still not a literal version is
// skipped rather than guessed.
const MAVEN_PROPERTY_RE = /<([\w.-]+)>([^<>]+)<\/\1>/g;
const MAVEN_DEPENDENCIES_BLOCK_RE = /<dependencies>([\s\S]*?)<\/dependencies>/;
const MAVEN_DEPENDENCY_BLOCK_RE = /<dependency>([\s\S]*?)<\/dependency>/g;

function extractMavenProperties(raw: string): Record<string, string> {
  const propsMatch = /<properties>([\s\S]*?)<\/properties>/.exec(raw);
  if (!propsMatch) return {};
  const props: Record<string, string> = {};
  let m: RegExpExecArray | null;
  MAVEN_PROPERTY_RE.lastIndex = 0;
  while ((m = MAVEN_PROPERTY_RE.exec(propsMatch[1])) !== null) {
    props[m[1]] = m[2].trim();
  }
  return props;
}

function resolveMavenVersion(raw: string, properties: Record<string, string>): string | null {
  const trimmed = raw.trim();
  const propRef = /^\$\{([\w.-]+)\}$/.exec(trimmed);
  const resolved = propRef ? properties[propRef[1]] : trimmed;
  if (!resolved) return null;
  // Only a literal release version is queryable with confidence — a range
  // ("[1.0,2.0)"), another unresolved "${...}", or "RELEASE"/"LATEST" is skipped.
  return /^\d+(\.\d+){0,3}([.-][\w]+)?$/.test(resolved) ? resolved : null;
}

/**
 * The real, top-level <dependencies> block content, or null if there isn't
 * one. <dependencyManagement>'s nested block of the same shape is stripped
 * first, or a naive regex would find that one instead.
 */
export function extractMavenDependenciesBlock(raw: string): string | null {
  const withoutManagement = raw.replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/, "");
  return MAVEN_DEPENDENCIES_BLOCK_RE.exec(withoutManagement)?.[1] ?? null;
}

export function parsePomXmlDependencies(raw: string): DeclaredDependency[] {
  const properties = extractMavenProperties(raw);
  const depsBlock = extractMavenDependenciesBlock(raw);
  if (depsBlock === null) return [];

  const deps: DeclaredDependency[] = [];
  let m: RegExpExecArray | null;
  MAVEN_DEPENDENCY_BLOCK_RE.lastIndex = 0;
  while ((m = MAVEN_DEPENDENCY_BLOCK_RE.exec(depsBlock)) !== null) {
    const block = m[1];
    const groupId = /<groupId>([^<]+)<\/groupId>/.exec(block)?.[1]?.trim();
    const artifactId = /<artifactId>([^<]+)<\/artifactId>/.exec(block)?.[1]?.trim();
    const rawVersion = /<version>([^<]+)<\/version>/.exec(block)?.[1];
    if (!groupId || !artifactId || !rawVersion) continue;

    const version = resolveMavenVersion(rawVersion, properties);
    if (!version) continue;

    deps.push({ name: `${groupId}:${artifactId}`, declaredRange: rawVersion.trim(), version });
  }
  return deps;
}

/** The manifest-range fallback for one ecosystem: packages to query plus how many dependencies were declared. Throws on unparseable JSON. */
function manifestPackages(ecosystem: OsvEcosystem, file: string, raw: string): { packages: ScannedPackage[]; declared: number } {
  const declared = (deps: DeclaredDependency[], extra: Partial<ScannedPackage> = {}) =>
    deps.map((d) => ({ ecosystem, name: d.name, version: d.version, direct: true, dev: null, file, exact: false, declaredRange: d.declaredRange, ...extra }));

  if (ecosystem === "npm") return npmManifestPackages(JSON.parse(raw) as PackageJsonShape);
  if (ecosystem === "PyPI") {
    const deps = parsePipRequirements(raw);
    // A line skipped for having no version is still declared, just not queryable.
    const total = raw
      .split(/\r?\n/)
      .map((l) => l.split("#")[0].trim())
      .filter((l) => l && !/^(-|git\+|https?:|\.\/|\.\.\/)/i.test(l)).length;
    return { packages: declared(deps), declared: total };
  }
  if (ecosystem === "Packagist") {
    const composer = JSON.parse(raw) as { require?: Record<string, string>; "require-dev"?: Record<string, string> };
    const packages: ScannedPackage[] = [];
    let count = 0;
    for (const [section, dev] of [["require", false], ["require-dev", true]] as const) {
      for (const [name, range] of Object.entries(composer[section] ?? {})) {
        if (COMPOSER_PLATFORM_PACKAGE_RE.test(name)) continue;
        count++;
        const version = typeof range === "string" ? minVersionFromRange(range) : null;
        if (version) packages.push({ ecosystem, name, version, direct: true, dev, file, exact: false, declaredRange: range });
      }
    }
    return { packages, declared: count };
  }
  if (ecosystem === "Go") {
    const deps = parseGoModRequire(raw);
    return { packages: deps.map((d) => ({ ...declared([d])[0], direct: !/\/\/\s*indirect/.test(d.declaredRange) })), declared: deps.length };
  }
  // Maven (pom.xml)
  const deps = parsePomXmlDependencies(raw);
  const block = extractMavenDependenciesBlock(raw);
  return { packages: declared(deps), declared: block !== null ? (block.match(MAVEN_DEPENDENCY_BLOCK_RE) ?? []).length : deps.length };
}

// ---- Collecting packages from the repo's files -------------------------------

export type CollectedPackages = {
  packages: ScannedPackage[];
  files: DependencyInventoryFile[];
  /** Dependencies found, including manifest entries whose range couldn't be reduced to a version. */
  declared: number;
  notes: string[];
};

function fromLockfile(p: LockfilePackage, file: string): ScannedPackage {
  return {
    ecosystem: p.ecosystem,
    name: p.name,
    version: p.version,
    direct: p.direct,
    dev: p.dev ?? null,
    ...(p.optional ? { optional: true } : {}),
    ...(p.introducedVia ? { introducedVia: p.introducedVia } : {}),
    ...(p.dependsOn ? { dependsOn: p.dependsOn } : {}),
    file,
    exact: true,
  };
}

/**
 * Pure: turns the repo-root files that were found (name → content) into
 * the packages to check — a lockfile per ecosystem where one is present
 * and parses, else that ecosystem's manifest ranges.
 */
export function collectDependencyPackages(contents: Record<string, string>): CollectedPackages {
  const packages: ScannedPackage[] = [];
  const files: DependencyInventoryFile[] = [];
  const notes: string[] = [];
  let declared = 0;

  for (const ecosystem of ECOSYSTEM_ORDER) {
    const present = LOCKFILES.filter((l) => l.ecosystem === ecosystem && contents[l.file] !== undefined);
    let usedLockfile = false;
    for (const lock of present) {
      try {
        const parsed = lock.parse(contents[lock.file], lock.companion ? contents[lock.companion] ?? null : null);
        packages.push(...parsed.packages.map((p) => fromLockfile(p, lock.file)));
        files.push({ file: lock.file, ecosystem, kind: "lockfile", graph: parsed.hasGraph });
        declared += parsed.packages.length;
        usedLockfile = true;
        const ignored = present.filter((l) => l !== lock).map((l) => l.file);
        if (ignored.length) notes.push(`${lock.file} was used for ${ecosystem}; ${ignored.join(", ")} also present and not read.`);
        break;
      } catch (err) {
        notes.push(`${lock.file} could not be parsed (${(err as Error).message}).`);
      }
    }
    if (usedLockfile) continue;

    const manifest = MANIFEST_FALLBACK[ecosystem];
    if (!manifest || contents[manifest] === undefined) continue;
    try {
      const m = manifestPackages(ecosystem, manifest, contents[manifest]);
      packages.push(...m.packages);
      files.push({ file: manifest, ecosystem, kind: "manifest", graph: false });
      declared += m.declared;
      if (present.length) notes.push(`Fell back to ${manifest}'s declared ranges for ${ecosystem}.`);
      const skipped = m.declared - m.packages.length;
      if (skipped > 0) notes.push(`${skipped} of ${m.declared} dependencies declared in ${manifest} had a version range that couldn't be reduced to a concrete version and were not queried.`);
    } catch {
      notes.push(`${manifest} could not be parsed.`);
    }
  }
  return { packages, files, declared, notes };
}

/** Merges duplicates (same ecosystem/name/version from one file) and orders direct packages first, so a cap drops the deepest transitive ones. */
function dedupeAndOrder(packages: ScannedPackage[]): ScannedPackage[] {
  const byKey = new Map<string, ScannedPackage>();
  for (const p of packages) {
    const key = `${p.ecosystem}:${packageKey(p.name, p.version)}`;
    if (!byKey.has(key)) byKey.set(key, p);
  }
  const rank = (p: ScannedPackage) => (p.direct === true ? 0 : p.direct === null ? 1 : 2);
  return [...byKey.values()].sort(
    (a, b) =>
      rank(a) - rank(b) ||
      ECOSYSTEM_ORDER.indexOf(a.ecosystem) - ECOSYSTEM_ORDER.indexOf(b.ecosystem) ||
      (a.introducedVia?.length ?? 0) - (b.introducedVia?.length ?? 0) ||
      a.name.localeCompare(b.name) ||
      a.version.localeCompare(b.version)
  );
}

// ---- Evaluating packages against OSV.dev -----------------------------------

const SEVERITY_ORDER = ["low", "medium", "high", "critical"] as const;

type Evaluated = {
  findings: Finding[];
  inventory: DependencyInventory;
  checked: number;
  notes: string[];
  error?: string;
};

function scopeOf(p: ScannedPackage): "required" | "optional" | undefined {
  if (p.dev === true || p.optional) return "optional";
  if (p.dev === false) return "required";
  return undefined;
}

function describeInstance(p: ScannedPackage): string {
  if (p.direct === true) return "a direct dependency";
  if (p.direct === false) {
    return p.introducedVia?.length
      ? `a transitive dependency, introduced via ${[...p.introducedVia, packageKey(p.name, p.version)].join(" > ")}`
      : "a transitive dependency";
  }
  return "listed in the lockfile (it doesn't record whether the dependency is direct or transitive)";
}

/** One finding per vulnerable package name (all its vulnerable installed versions together), keeping the checkId stable across versions. */
function buildFinding(
  slug: DependencyEcosystemSlug,
  instances: Array<{ pkg: ScannedPackage; vulnIds: string[]; fixedVersion: string | null }>,
  details: Map<string, OsvVulnDetail>
): Finding {
  const first = instances[0].pkg;
  const name = first.name;
  const versions = instances.map((i) => i.pkg.version);
  const vulnIds = [...new Set(instances.flatMap((i) => i.vulnIds))].sort();
  const known = vulnIds.map((id) => details.get(id)).filter((d): d is OsvVulnDetail => !!d);
  const cveIds = [...new Set([...cveIdsOf(known), ...cveIdsOf(vulnIds.map((id) => ({ id })))])].sort();
  const exact = first.exact;

  // Lockfile-exact: the advisories' own ratings. Manifest-range: the version
  // is only a lower bound, so the finding stays at the long-standing medium
  // rather than escalating on an install we haven't evidenced.
  let severity: Finding["severity"] = "medium";
  if (exact) {
    const rated = known.map(osvSeverity).filter((s): s is NonNullable<typeof s> => !!s);
    if (rated.length) severity = rated.reduce((a, b) => (SEVERITY_ORDER.indexOf(b) > SEVERITY_ORDER.indexOf(a) ? b : a));
  }
  const cvss = known.map(osvCvss).filter((c): c is NonNullable<typeof c> => !!c).sort((a, b) => b.score - a.score)[0];

  // CVE ids where advisories have them, plus the OSV id of any advisory that has none.
  const shownIds = [...cveIds, ...vulnIds.filter((id) => cveIdsOf([details.get(id) ?? { id }]).length === 0)];
  const idList = shownIds.slice(0, 8).join(", ") + (shownIds.length > 8 ? ` (+${shownIds.length - 8} more)` : "");
  const count = vulnIds.length;

  let detail: string;
  if (exact) {
    const parts = instances.map((i) => {
      const fix = i.fixedVersion ? ` Fixed in ${i.fixedVersion}.` : " OSV.dev names no single fixed version for every advisory found.";
      const dev = i.pkg.dev === true ? " Development-only dependency." : "";
      return `${name} ${i.pkg.version} is ${describeInstance(i.pkg)}.${dev}${fix}`;
    });
    detail = `OSV.dev reports ${count} known vulnerabilit${count === 1 ? "y" : "ies"} (${idList}) affecting ${name} ${versions.join(" and ")}, the exact version${versions.length === 1 ? "" : "s"} recorded in ${first.file} (lockfile-exact). ${parts.join(" ")}`;
  } else {
    const fix = instances[0].fixedVersion ? ` Fixed in ${instances[0].fixedVersion}.` : "";
    detail = `OSV.dev reports ${count} known vulnerabilit${count === 1 ? "y" : "ies"} (${idList}) affecting ${name} at version ${first.version}, the minimum version resolvable from the range declared in ${first.file} ("${first.declaredRange ?? first.version}"). This is a manifest-range check, not a lockfile-exact match — the actual installed version may differ.${fix}`;
  }

  // Remediation speaks to the instance that matters most: a direct one if
  // any, else the one with the shortest route in.
  const lead = [...instances].sort((a, b) => (a.pkg.direct === true ? -1 : 0) - (b.pkg.direct === true ? -1 : 0) || (a.pkg.introducedVia?.length ?? 99) - (b.pkg.introducedVia?.length ?? 99))[0];
  const fixedAll = instances.every((i) => i.fixedVersion) && new Set(instances.map((i) => i.fixedVersion)).size === 1 ? instances[0].fixedVersion : lead.fixedVersion;

  return {
    checkId: `dependency-manifest.${slug}:${name}`,
    severity,
    title: `Vulnerable dependency: ${name}@${versions.join(", ")}`,
    detail,
    remediation: dependencyVulnerableRemediation(name, slug, {
      versionSource: exact ? "lockfile" : "manifest",
      file: first.file,
      fixedVersion: fixedAll,
      direct: lead.pkg.direct,
      introducedVia: lead.pkg.introducedVia,
    }),
    cveIds,
    ...(cvss ? { cvssScore: cvss.score, cvssVector: cvss.vector } : {}),
    metadata: {
      ecosystem: first.ecosystem,
      packageName: name,
      versionSource: exact ? "lockfile" : "manifest",
      file: first.file,
      osvIds: vulnIds,
      versions: instances.map((i) => ({
        version: i.pkg.version,
        direct: i.pkg.direct,
        dev: i.pkg.dev,
        ...(i.pkg.introducedVia ? { introducedVia: i.pkg.introducedVia } : {}),
        fixedVersion: i.fixedVersion,
      })),
    },
  };
}

function emptyInventory(files: DependencyInventoryFile[], packages: ScannedPackage[], total: number, lookup: "completed" | "failed"): DependencyInventory {
  const fileIndex = new Map(files.map((f, i) => [f.file, i]));
  const index = new Map(packages.map((p, i) => [`${p.ecosystem}:${packageKey(p.name, p.version)}`, i]));
  return {
    schemaVersion: 1,
    files,
    packages: packages.map((p) => {
      const deps = (p.dependsOn ?? []).map((k) => index.get(`${p.ecosystem}:${k}`)).filter((i): i is number => i !== undefined);
      const scope = scopeOf(p);
      return {
        ecosystem: p.ecosystem,
        name: p.name,
        version: p.version,
        direct: p.direct,
        ...(scope ? { scope } : {}),
        fileIndex: fileIndex.get(p.file) ?? 0,
        ...(deps.length ? { dependsOn: deps } : {}),
      };
    }),
    totalPackages: total,
    truncated: total > packages.length,
    vulnerabilityLookup: lookup,
    advisories: [],
  };
}

/**
 * Checks collected packages against OSV.dev and builds findings plus the
 * inventory. `error` is set (and findings are empty) when the OSV.dev batch
 * lookup failed — the caller reports that as an "error" result.
 */
export async function evaluateDependencyPackages(collected: CollectedPackages): Promise<Evaluated> {
  const ordered = dedupeAndOrder(collected.packages);
  const queried = ordered.slice(0, MAX_PACKAGES_QUERIED);
  const notes: string[] = [];
  if (ordered.length > queried.length) {
    notes.push(`Only ${MAX_PACKAGES_QUERIED} of ${ordered.length} packages were checked against OSV.dev (direct dependencies first); the rest are not in this result.`);
  }

  const batch = await queryOsvBatch(queried.map((p) => ({ ecosystem: p.ecosystem, name: p.name, version: p.version })));
  if (!batch.ok) {
    return {
      findings: [],
      inventory: emptyInventory(collected.files, queried, ordered.length, "failed"),
      checked: 0,
      notes,
      error: batch.error,
    };
  }

  const affected = queried.map((pkg, i) => ({ pkg, ids: batch.vulnIds[i] })).filter((a) => a.ids.length > 0);
  const allIds = [...new Set(affected.flatMap((a) => a.ids))].sort();
  const toFetch = allIds.slice(0, MAX_VULN_DETAILS);
  const { details, failed } = await fetchOsvVulnDetails(toFetch, { concurrency: QUERY_CONCURRENCY });
  const missing = allIds.length - details.size;
  if (missing > 0) {
    notes.push(`Advisory details for ${missing} of ${allIds.length} OSV.dev advisories could not be fetched${failed.length ? ` (${failed.slice(0, 5).join(", ")}${failed.length > 5 ? ", ..." : ""})` : ""}; those packages are still reported, with fewer CVE ids and no fixed version.`);
  }

  // A withdrawn advisory no longer claims anything.
  const live = (ids: string[]) => ids.filter((id) => !details.get(id)?.withdrawn);
  const inventory = emptyInventory(collected.files, queried, ordered.length, "completed");
  const advisoryIds = new Set<string>();
  const vulnerable: Array<{ pkg: ScannedPackage; vulnIds: string[]; fixedVersion: string | null }> = [];

  queried.forEach((pkg, i) => {
    const ids = live(batch.vulnIds[i]);
    if (ids.length === 0) return;
    const vulnDetails = ids.map((id) => details.get(id));
    const fixedVersion = vulnDetails.every((d) => d) ? fixedVersionFromVulns(vulnDetails as OsvVulnDetail[], pkg.ecosystem, pkg.name, pkg.version) : null;
    inventory.packages[i].vulnIds = ids;
    if (fixedVersion) inventory.packages[i].fixedVersion = fixedVersion;
    ids.forEach((id) => advisoryIds.add(id));
    vulnerable.push({ pkg, vulnIds: ids, fixedVersion });
  });

  inventory.advisories = [...advisoryIds].sort().map((id) => {
    const d = details.get(id);
    const severity = d ? osvSeverity(d) : null;
    const cvss = d ? osvCvss(d) : null;
    return {
      id,
      cveIds: cveIdsOf(d ? [d] : [{ id }]),
      ...(severity ? { severity } : {}),
      ...(cvss ? { cvssVector: cvss.vector, cvssScore: cvss.score } : {}),
      ...(d?.summary ? { summary: d.summary.slice(0, 200) } : {}),
    };
  });

  const findings: Finding[] = [];
  for (const ecosystem of ECOSYSTEM_ORDER) {
    const slug = ECOSYSTEM_SLUG[ecosystem];
    const byName = new Map<string, typeof vulnerable>();
    for (const v of vulnerable.filter((v) => v.pkg.ecosystem === ecosystem)) {
      byName.set(v.pkg.name, [...(byName.get(v.pkg.name) ?? []), v]);
    }
    // Deterministic order (alphabetical) so the cap and the checkId-keyed
    // New/Fixed diff behave consistently run to run.
    const names = [...byName.keys()].sort((a, b) => a.localeCompare(b));
    for (const name of names.slice(0, MAX_FINDINGS)) {
      const instances = byName.get(name)!.sort((a, b) => a.pkg.version.localeCompare(b.pkg.version));
      findings.push(buildFinding(slug, instances, details));
    }
    const remaining = names.length - MAX_FINDINGS;
    if (remaining > 0) {
      const sourceFiles = [...new Set(vulnerable.filter((v) => v.pkg.ecosystem === ecosystem).map((v) => v.pkg.file))].join(", ");
      findings.push({
        checkId: `dependency-manifest.additional-vulnerable:${slug}`,
        severity: "info",
        title: `${remaining} further vulnerable ${slug} dependenc${remaining === 1 ? "y" : "ies"} not listed individually`,
        detail: `${names.length} vulnerable ${slug} packages were found in total (from ${sourceFiles}); the first ${MAX_FINDINGS} are listed above. Additional: ${names.slice(MAX_FINDINGS, MAX_FINDINGS + 10).join(", ")}${remaining > 10 ? ` (+${remaining - 10} more)` : ""}.`,
      });
    }
  }

  return { findings, inventory, checked: queried.length, notes };
}

/**
 * The manifest-only npm path, kept for local verification without a GitHub
 * token/repo — the half of this module that must be provable against real
 * OSV.dev data alone. Throws if the OSV.dev lookup fails.
 */
export async function buildDependencyFindings(
  pkg: PackageJsonShape
): Promise<{ findings: Finding[]; dependenciesDeclared: number; dependenciesChecked: number; note?: string }> {
  const m = npmManifestPackages(pkg);
  const collected: CollectedPackages = { packages: m.packages, files: [{ file: "package.json", ecosystem: "npm", kind: "manifest", graph: false }], declared: m.declared, notes: [] };
  const evaluated = await evaluateDependencyPackages(collected);
  if (evaluated.error) throw new Error(evaluated.error);
  const notes = [...collected.notes, ...evaluated.notes];
  return { findings: evaluated.findings, dependenciesDeclared: m.declared, dependenciesChecked: evaluated.checked, ...(notes.length ? { note: notes.join(" ") } : {}) };
}

// ---- GitHub ------------------------------------------------------------------

type RepoFile = { status: "ok"; content: string } | { status: "missing" } | { status: "error"; reason: string };

async function fetchRepoFile(githubRepo: string, path: string, token: string): Promise<RepoFile> {
  try {
    const res = await fetch(`${githubApi}/repos/${githubRepo}/contents/${encodeURIComponent(path)}`, {
      headers: ghHeaders(token, true),
      signal: AbortSignal.timeout(GITHUB_API_TIMEOUT_MS),
    });
    if (res.status === 404) return { status: "missing" };
    if (!res.ok) return { status: "error", reason: `HTTP ${res.status}` };
    const length = Number(res.headers.get("content-length") ?? 0);
    if (length > MAX_FILE_BYTES) return { status: "error", reason: `larger than ${MAX_FILE_BYTES / 1024 / 1024} MB` };
    const text = await res.text();
    if (text.length > MAX_FILE_BYTES) return { status: "error", reason: `larger than ${MAX_FILE_BYTES / 1024 / 1024} MB` };
    return { status: "ok", content: text };
  } catch (err) {
    return { status: "error", reason: (err as Error).message };
  }
}

/** Names of the files at the repo root (default branch), or an error string. */
async function listRepoRoot(githubRepo: string, token: string): Promise<Set<string> | string> {
  try {
    const res = await fetch(`${githubApi}/repos/${githubRepo}/contents/`, {
      headers: ghHeaders(token),
      signal: AbortSignal.timeout(GITHUB_API_TIMEOUT_MS),
    });
    if (!res.ok) return `listing the repository root returned HTTP ${res.status}`;
    const body = (await res.json()) as unknown;
    if (!Array.isArray(body)) return "listing the repository root returned an unexpected response";
    return new Set(body.filter((e) => e && typeof e === "object" && (e as { type?: string }).type === "file").map((e) => String((e as { name?: unknown }).name)));
  } catch (err) {
    return `listing the repository root failed: ${(err as Error).message}`;
  }
}

// ---- Entry point ---------------------------------------------------------

/**
 * Scans the connected repo's root lockfiles (else manifests) against
 * OSV.dev. Never throws.
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
    const root = await listRepoRoot(githubRepo, token);
    if (typeof root === "string") {
      return { status: "error", repo: githubRepo, findings: [], note: `Could not read ${githubRepo}: ${root}. No dependency verdict for this scan.` };
    }
    const candidates = CANDIDATE_FILES.filter((f) => root.has(f));
    const meaningful = candidates.filter((f) => f !== "pyproject.toml" || root.has("poetry.lock"));
    if (meaningful.length === 0) {
      return {
        status: "not_applicable",
        repo: githubRepo,
        findings: [],
        note: "No supported lockfile (package-lock.json, yarn.lock, pnpm-lock.yaml, poetry.lock, Pipfile.lock, composer.lock, go.sum, Gemfile.lock, Cargo.lock, packages.lock.json, gradle.lockfile) or manifest (package.json, requirements.txt, composer.json, go.mod, pom.xml) found at the repository root — nothing to scan.",
      };
    }

    const fetched = await Promise.all(candidates.map(async (f) => [f, await fetchRepoFile(githubRepo, f, token)] as const));
    const contents: Record<string, string> = {};
    const fetchNotes: string[] = [];
    for (const [file, r] of fetched) {
      if (r.status === "ok") contents[file] = r.content;
      else if (r.status === "error") fetchNotes.push(`${file} could not be read (${r.reason}).`);
    }

    const collected = collectDependencyPackages(contents);
    const notes = [...fetchNotes, ...collected.notes];
    if (collected.files.length === 0) {
      // Files exist but none could be read or parsed: that's a failure to look, not "nothing to scan".
      return { status: "error", repo: githubRepo, findings: [], note: `Dependency files were found but none could be read. ${notes.join(" ")}`.trim() };
    }

    const evaluated = await evaluateDependencyPackages(collected);
    notes.push(...evaluated.notes);
    if (evaluated.error) {
      return {
        status: "error",
        repo: githubRepo,
        findings: [],
        inventory: evaluated.inventory,
        note: `${evaluated.error}. No vulnerability verdict for this scan — this is not a clean result. ${notes.join(" ")}`.trim(),
      };
    }

    // Typosquat risk is independent of the OSV vulnerability lookup above —
    // it only needs the package names already collected. Run it once OSV
    // has succeeded so a failed lookup there still means "no verdict at
    // all" (above), never a partial result with only the heuristic signal.
    const typosquatCandidates = findTyposquatCandidates(collected.packages);
    const typosquatAssessment = typosquatCandidates.length > 0 ? await assessTyposquatCandidates(typosquatCandidates) : { findings: [], checked: 0, notes: [] };
    notes.push(...typosquatAssessment.notes);

    const scanned = collected.files.map((f) => f.file);
    return {
      status: "completed",
      repo: githubRepo,
      manifestsScanned: scanned,
      lockfilesScanned: collected.files.filter((f) => f.kind === "lockfile").map((f) => f.file),
      dependenciesDeclared: collected.declared,
      dependenciesChecked: evaluated.checked,
      findings: [...evaluated.findings, ...typosquatAssessment.findings.map(buildTyposquatFinding)],
      inventory: evaluated.inventory,
      ...(notes.length ? { note: notes.join(" ") } : {}),
    };
  } catch (err) {
    // Backstop: this function's contract is that it never throws. An
    // unexpected failure is an error, never a clean "nothing found".
    return { status: "error", repo: githubRepo, findings: [], note: `dependency scan could not complete: ${(err as Error).message}` };
  }
}

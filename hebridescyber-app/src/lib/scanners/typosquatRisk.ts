// Typosquat / supply-chain package risk scoring — extends
// dependencyManifest.ts's package inventory with a second, independent
// check: is a declared dependency's name a likely typosquat of a
// well-known package?
//
// A name match alone is not evidence of anything — thousands of small,
// legitimately-named packages exist. This check only reports when BOTH:
//   1. Offline, no network: the package name is exactly one character
//      away (Levenshtein distance 1 — a single insertion, deletion or
//      substitution) from a name in a small, hand-curated list of
//      well-known npm/PyPI packages (POPULAR_PACKAGES below). This is the
//      real pattern — "loadsh" for "lodash", "corss-env" for
//      "cross-env" — not a vague similarity score.
//   2. Online, bounded to only the names signal 1 already flagged: the
//      real registry (registry.npmjs.org / pypi.org — no key, both
//      already allowed network destinations for this product) shows the
//      candidate is a published-but-barely-developed package sitting
//      next to a mature, heavily-released one. Concretely: the candidate
//      has fewer than LOW_VERSION_COUNT_THRESHOLD releases while the
//      package it resembles has at least POPULAR_MIN_VERSION_COUNT. A
//      real typosquat is cheap to publish once and never maintained; this
//      does not age out the way a "published recently" check would —
//      "loadsh" has sat unmaintained at 4 releases since 2018 and is a
//      real, still-live typosquat of lodash (117 releases and counting),
//      confirmed against the real registry while building this check.
//
// A candidate missing from the registry (404) is never reported — that
// could mean it was already removed for being malicious, or it could be
// an unrelated private/internal package name that happens to be one edit
// from a popular one. This check has no way to tell the two apart, and
// the "never guess" rule means skip rather than assume the worse one. The
// same applies to a failed registry lookup (network/5xx): absence of
// evidence, not evidence of a clean result — never guessed either way.
//
// This is a heuristic signal, not a confirmed-malicious verdict, so
// severity stays at medium and the finding text says so explicitly.

import type { Finding } from "./index";
import type { OsvEcosystem } from "./dependencyLockfiles";
import { typosquatRiskRemediation } from "./remediationText";

export type TyposquatEcosystem = "npm" | "PyPI";

// ---- Curated popular-package lists -----------------------------------------
//
// Hand-picked, deliberately small (a few hundred entries, not an attempt at
// a full top-N download ranking): widely known packages whose name a real
// typosquat would actually try to mimic. Same "committed static table,
// refreshed by hand" pattern as TAKEOVER_PROVIDERS/NVD_CPE_BY_NAME
// elsewhere in this codebase. Intentionally-close legitimate pairs (e.g. a
// deprecated package and its modern replacement) are both listed, so each
// suppresses a false flag on the other via the "already in the popular
// list" exclusion in findTyposquatCandidates().
export const POPULAR_PACKAGES: Record<TyposquatEcosystem, string[]> = {
  npm: [
    "react", "react-dom", "react-router", "react-router-dom", "redux", "react-redux",
    "vue", "vue-router", "vuex", "angular", "@angular/core", "svelte",
    "lodash", "underscore", "ramda", "moment", "dayjs", "date-fns",
    "express", "koa", "fastify", "hapi", "next", "nuxt", "gatsby",
    "webpack", "rollup", "vite", "esbuild", "parcel", "babel-core", "@babel/core",
    "typescript", "eslint", "prettier", "jest", "mocha", "chai", "sinon", "vitest",
    "axios", "node-fetch", "request", "superagent", "got", "undici",
    "chalk", "commander", "yargs", "inquirer", "minimist", "dotenv",
    "uuid", "nanoid", "classnames", "clsx", "immer", "zustand",
    "jquery", "bootstrap", "tailwindcss", "sass", "postcss", "less",
    "socket.io", "ws", "graphql", "apollo-server", "mongoose", "sequelize",
    "prisma", "knex", "pg", "mysql2", "redis", "ioredis",
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "helmet", "cors",
    "body-parser", "multer", "cookie-parser", "morgan", "winston", "pino",
    "rxjs", "lodash.debounce", "core-js", "regenerator-runtime", "tslib",
    "semver", "glob", "rimraf", "mkdirp", "fs-extra", "chokidar",
    "async", "bluebird", "q", "co", "through2", "readable-stream",
    "cross-env", "cross-spawn", "concurrently", "npm-run-all", "husky",
    "lint-staged", "nodemon", "pm2", "forever", "supervisor",
    "styled-components", "emotion", "@emotion/react", "framer-motion",
    "d3", "three", "chart.js", "leaflet", "mapbox-gl",
    "stripe", "aws-sdk", "@aws-sdk/client-s3", "firebase", "@supabase/supabase-js",
    "typeorm", "class-validator", "class-transformer", "zod", "yup", "joi",
    "vue-cli", "@vue/cli", "create-react-app", "vite-plugin-react",
  ],
  PyPI: [
    "requests", "urllib3", "httpx", "aiohttp", "flask", "django", "fastapi",
    "numpy", "pandas", "scipy", "matplotlib", "seaborn", "scikit-learn",
    "tensorflow", "torch", "keras", "transformers", "huggingface-hub",
    "pytest", "unittest2", "nose", "tox", "coverage", "mock",
    "sqlalchemy", "psycopg2", "pymongo", "redis", "celery",
    "boto3", "botocore", "google-cloud-storage", "azure-storage-blob",
    "pyyaml", "jinja2", "click", "typer", "argparse",
    "pillow", "opencv-python", "imageio", "scikit-image",
    "beautifulsoup4", "lxml", "html5lib", "scrapy", "selenium",
    "cryptography", "pycryptodome", "pyjwt", "passlib", "bcrypt",
    "pydantic", "marshmallow", "attrs", "dataclasses-json",
    "setuptools", "wheel", "pip", "virtualenv", "poetry", "pipenv",
    "gunicorn", "uvicorn", "waitress", "werkzeug",
    "six", "python-dateutil", "pytz", "tzdata", "arrow",
    "colorama", "tqdm", "rich", "tabulate", "prettytable",
    "docutils", "sphinx", "markdown", "mistune",
    "pyparsing", "regex", "chardet", "charset-normalizer", "idna",
    "certifi", "cffi", "cachetools", "decorator", "wrapt",
  ],
};

// Below this length a distance-1 edit is too common to be meaningful
// ("ws" vs "js" would otherwise trip it).
const MIN_NAME_LENGTH = 4;

const MAX_EDIT_DISTANCE = 1;

/**
 * Standard Levenshtein edit distance (insert/delete/substitute). Both
 * inputs are real package names (always short), so no length guard beyond
 * what findTyposquatCandidates already applies before calling this.
 */
export function levenshteinDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const curr = [i];
    for (let j = 1; j <= b.length; j++) {
      curr[j] =
        a[i - 1] === b[j - 1]
          ? prev[j - 1]
          : 1 + Math.min(prev[j - 1], prev[j], curr[j - 1]);
    }
    prev = curr;
  }
  return prev[b.length];
}

/** PyPI names are case-insensitive and treat -, _, . as equivalent (PEP 503). npm names are just lower-cased. */
function normalisePackageName(ecosystem: TyposquatEcosystem, name: string): string {
  const lower = name.toLowerCase();
  return ecosystem === "PyPI" ? lower.replace(/[-_.]+/g, "-") : lower;
}

export type TyposquatCandidate = {
  ecosystem: TyposquatEcosystem;
  /** The package name exactly as declared/installed. */
  name: string;
  /** The popular package it is one edit away from. */
  resembles: string;
};

/**
 * Pure, offline: which declared packages are exactly one character away
 * from a well-known package of the same ecosystem. Only npm/PyPI packages
 * are considered — the other ecosystems this product scans have no
 * curated list yet. Never throws, makes no network calls.
 */
export function findTyposquatCandidates(packages: Array<{ ecosystem: OsvEcosystem; name: string }>): TyposquatCandidate[] {
  const results: TyposquatCandidate[] = [];
  const seen = new Set<string>();

  for (const pkg of packages) {
    if (pkg.ecosystem !== "npm" && pkg.ecosystem !== "PyPI") continue;
    const ecosystem = pkg.ecosystem;
    if (pkg.name.length < MIN_NAME_LENGTH) continue;

    const normalisedName = normalisePackageName(ecosystem, pkg.name);
    const dedupeKey = `${ecosystem}:${normalisedName}`;
    if (seen.has(dedupeKey)) continue;

    const popular = POPULAR_PACKAGES[ecosystem];
    if (popular.some((p) => normalisePackageName(ecosystem, p) === normalisedName)) continue; // it IS the popular package

    let best: string | null = null;
    for (const candidate of popular) {
      const normalisedCandidate = normalisePackageName(ecosystem, candidate);
      if (Math.abs(normalisedCandidate.length - normalisedName.length) > MAX_EDIT_DISTANCE) continue;
      if (levenshteinDistance(normalisedName, normalisedCandidate) === MAX_EDIT_DISTANCE) {
        if (!best || candidate < best) best = candidate;
      }
    }

    if (best) {
      seen.add(dedupeKey);
      results.push({ ecosystem, name: pkg.name, resembles: best });
    }
  }

  return results;
}

// ---- Live registry corroboration -------------------------------------------

const REGISTRY_TIMEOUT_MS = 10_000;

/** Bounds live registry fetches per scan — findTyposquatCandidates can only ever return offline, unbounded-cost matches. */
export const MAX_TYPOSQUAT_CANDIDATES = 20;

const LOW_VERSION_COUNT_THRESHOLD = 10;
const POPULAR_MIN_VERSION_COUNT = 30;

export type PackageRegistryMetadata =
  | { status: "found"; createdAt: string | null; versionCount: number }
  | { status: "not_found" }
  | { status: "error"; reason: string };

async function fetchNpmMetadata(name: string): Promise<PackageRegistryMetadata> {
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`, { signal: AbortSignal.timeout(REGISTRY_TIMEOUT_MS) });
    if (res.status === 404) return { status: "not_found" };
    if (!res.ok) return { status: "error", reason: `HTTP ${res.status}` };
    const body = (await res.json()) as { time?: { created?: string }; versions?: Record<string, unknown> };
    return { status: "found", createdAt: body.time?.created ?? null, versionCount: Object.keys(body.versions ?? {}).length };
  } catch (err) {
    return { status: "error", reason: (err as Error).message };
  }
}

async function fetchPyPiMetadata(name: string): Promise<PackageRegistryMetadata> {
  try {
    const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, { signal: AbortSignal.timeout(REGISTRY_TIMEOUT_MS) });
    if (res.status === 404) return { status: "not_found" };
    if (!res.ok) return { status: "error", reason: `HTTP ${res.status}` };
    const body = (await res.json()) as { releases?: Record<string, Array<{ upload_time_iso_8601?: string }>> };
    const releases = body.releases ?? {};
    const uploadTimes = Object.values(releases)
      .flat()
      .map((f) => f.upload_time_iso_8601)
      .filter((t): t is string => !!t)
      .sort();
    return { status: "found", createdAt: uploadTimes[0] ?? null, versionCount: Object.keys(releases).length };
  } catch (err) {
    return { status: "error", reason: (err as Error).message };
  }
}

/** Overridable for tests; the default hits the real registries. */
export async function fetchPackageRegistryMetadata(ecosystem: TyposquatEcosystem, name: string): Promise<PackageRegistryMetadata> {
  return ecosystem === "npm" ? fetchNpmMetadata(name) : fetchPyPiMetadata(name);
}

export type TyposquatFinding = {
  ecosystem: TyposquatEcosystem;
  name: string;
  resembles: string;
  candidateVersionCount: number;
  candidateCreatedAt: string | null;
  popularVersionCount: number;
  popularCreatedAt: string | null;
};

/** Small helper so a 5-at-a-time cap on concurrent registry fetches needs no dependency. */
async function mapWithConcurrency<T, R>(items: T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

/**
 * Checks offline candidates against the real registry and keeps only the
 * ones with corroborating evidence. Never throws — a failed or missing
 * lookup drops that candidate from the result rather than failing the
 * whole check, and is counted in `notes`.
 */
export async function assessTyposquatCandidates(
  candidates: TyposquatCandidate[],
  fetchMetadata: (ecosystem: TyposquatEcosystem, name: string) => Promise<PackageRegistryMetadata> = fetchPackageRegistryMetadata
): Promise<{ findings: TyposquatFinding[]; checked: number; notes: string[] }> {
  const bounded = candidates.slice(0, MAX_TYPOSQUAT_CANDIDATES);
  const notes: string[] = [];
  if (candidates.length > bounded.length) {
    notes.push(`Only the first ${MAX_TYPOSQUAT_CANDIDATES} of ${candidates.length} name-similarity candidates were checked against the real package registry.`);
  }

  // Many candidates can resemble the same popular package; fetch each
  // distinct name (candidate or popular) at most once.
  const distinctNames = [...new Set(bounded.flatMap((c) => [`${c.ecosystem}:${c.name}`, `${c.ecosystem}:${c.resembles}`]))];
  const metadataResults = await mapWithConcurrency(distinctNames, 5, async (key) => {
    const sep = key.indexOf(":");
    const ecosystem = key.slice(0, sep) as TyposquatEcosystem;
    const name = key.slice(sep + 1);
    return [key, await fetchMetadata(ecosystem, name)] as const;
  });
  const metadata = new Map(metadataResults);

  let failed = 0;
  const findings: TyposquatFinding[] = [];
  for (const candidate of bounded) {
    const candidateMeta = metadata.get(`${candidate.ecosystem}:${candidate.name}`);
    const popularMeta = metadata.get(`${candidate.ecosystem}:${candidate.resembles}`);
    if (!candidateMeta || !popularMeta) continue;
    if (candidateMeta.status === "error" || popularMeta.status === "error") {
      failed++;
      continue;
    }
    if (candidateMeta.status !== "found" || popularMeta.status !== "found") continue; // 404 either side — no evidence, never guess

    if (candidateMeta.versionCount < LOW_VERSION_COUNT_THRESHOLD && popularMeta.versionCount >= POPULAR_MIN_VERSION_COUNT) {
      findings.push({
        ecosystem: candidate.ecosystem,
        name: candidate.name,
        resembles: candidate.resembles,
        candidateVersionCount: candidateMeta.versionCount,
        candidateCreatedAt: candidateMeta.createdAt,
        popularVersionCount: popularMeta.versionCount,
        popularCreatedAt: popularMeta.createdAt,
      });
    }
  }
  if (failed > 0) notes.push(`${failed} of ${bounded.length} registry lookups failed and could not be checked.`);

  return { findings, checked: bounded.length, notes };
}

function formatDate(iso: string | null): string {
  if (!iso) return "an unknown date";
  return iso.slice(0, 10);
}

/** Builds the Finding for one corroborated typosquat candidate. */
export function buildTyposquatFinding(f: TyposquatFinding): Finding {
  const ecosystemLabel = f.ecosystem === "npm" ? "npm" : "PyPI";
  return {
    checkId: `dependency-manifest.typosquat-risk:${f.name}`,
    severity: "medium",
    title: `Possible typosquat dependency: ${f.name} (resembles ${f.resembles})`,
    detail: `"${f.name}" is one character different from the well-known ${ecosystemLabel} package "${f.resembles}" — a common typosquatting pattern. "${f.resembles}" has ${f.popularVersionCount} published releases (first ${formatDate(f.popularCreatedAt)}); "${f.name}" has only ${f.candidateVersionCount} release${f.candidateVersionCount === 1 ? "" : "s"} (first ${formatDate(f.candidateCreatedAt)}). This is a heuristic signal, not a confirmed-malicious verdict — verify this is the package your project intended to depend on.`,
    remediation: typosquatRiskRemediation(ecosystemLabel, f.name, f.resembles),
    metadata: {
      ecosystem: f.ecosystem,
      packageName: f.name,
      resembles: f.resembles,
      candidateVersionCount: f.candidateVersionCount,
      popularVersionCount: f.popularVersionCount,
    },
  };
}

// Client-side JavaScript library detection and vulnerability matching,
// using the retire.js vulnerability repository (RetireJS/retire.js,
// Apache-2.0 — attribution in docs/THIRD-PARTY-NOTICES.md). It replaces a
// hand-kept list of 7 libraries with ~76 libraries and their published
// vulnerable version ranges.
//
// The data file is fetched at scan time from a PINNED commit (reproducible
// scans; bump RETIRE_DATA_COMMIT deliberately) and cached per process. It is
// deliberately not bundled: webapp.ts is reachable from API routes, and a
// 600 KB JSON import would ship inside every serverless function.
//
// Evidence rules:
//   - A library counts only when one of retire.js's own extractors matched:
//     the script URL (`uri`/`filename`), the script body (`filecontent`) or
//     the body's SHA-1 (`hashes`). `func` extractors need a JS runtime and
//     are not used.
//   - Vulnerable only when the detected version is inside a published range
//     (`atOrAbove` <= version < `below`). An unparseable version is never
//     guessed into a range.
//   - If the data can't be loaded, callers fall back to the legacy pattern
//     list — detection gets narrower, never wrong.
import { createHash } from "node:crypto";

export const RETIRE_DATA_COMMIT = "69016f934568b93ce2517073dc2ac99dba615215";
const RETIRE_DATA_URL = `https://raw.githubusercontent.com/RetireJS/retire.js/${RETIRE_DATA_COMMIT}/repository/jsrepository.json`;
const VERSION_TOKEN = "§§version§§";
// Dotted numbers plus an optional pre-release tag. A looser "[0-9][0-9a-z.]*"
// swallows filename suffixes ("3.7.1.min" from jquery-3.7.1.min.js).
const VERSION_PATTERN = "[0-9]+(?:\\.[0-9]+)*(?:[-.]?(?:alpha|beta|rc|pre|dev)[0-9.]*)?";

type RetireVuln = {
  below?: string;
  atOrAbove?: string;
  severity?: string;
  identifiers?: { summary?: string; CVE?: string[]; githubID?: string };
  info?: string[];
};
type RetireComponent = {
  vulnerabilities?: RetireVuln[];
  extractors?: { uri?: string[]; filename?: string[]; filecontent?: string[]; hashes?: Record<string, string> };
};
export type RetireRepository = Record<string, RetireComponent>;

export type RetireMatch = {
  component: string;
  version: string;
  vulnerabilities: Array<{ severity: "low" | "medium" | "high" | "critical"; summary: string; cveIds: string[]; below?: string }>;
};

let cached: RetireRepository | null = null;

/** The pinned retire.js repository, or null if it couldn't be loaded. */
export async function loadRetireRepository(): Promise<RetireRepository | null> {
  if (cached) return cached;
  try {
    const res = await fetch(RETIRE_DATA_URL, { signal: AbortSignal.timeout(15_000) });
    if (!res.ok) return null;
    const body = (await res.json()) as unknown;
    if (!body || typeof body !== "object") return null;
    cached = body as RetireRepository;
    return cached;
  } catch {
    return null;
  }
}

/** Test hook. */
export function setRetireRepositoryForTests(repo: RetireRepository | null): void {
  cached = repo;
}

const regexCache = new Map<string, RegExp | null>();
function compile(pattern: string): RegExp | null {
  if (regexCache.has(pattern)) return regexCache.get(pattern)!;
  let re: RegExp | null = null;
  try {
    re = new RegExp(pattern.split(VERSION_TOKEN).join(VERSION_PATTERN), "i");
  } catch {
    re = null; // a pattern JS can't compile is skipped, never guessed
  }
  regexCache.set(pattern, re);
  return re;
}

function firstVersion(patterns: string[] | undefined, text: string): string | null {
  for (const p of patterns ?? []) {
    const m = compile(p)?.exec(text);
    if (m?.[1]) return m[1].replace(/[._-]+$/, "");
  }
  return null;
}

/** Splits "1.12.4-beta.2" into comparable parts; null if it has no leading number. */
function parts(v: string): Array<number | string> | null {
  if (!/^\d/.test(v)) return null;
  return v.split(/[.\-+]/).filter(Boolean).map((p) => (/^\d+$/.test(p) ? Number(p) : p.toLowerCase()));
}

/**
 * Semver-ish comparison: numbers compare numerically; a pre-release tag sorts
 * before the release ("1.0.0-beta" < "1.0.0"). Null when either can't be read.
 */
export function compareRetireVersions(a: string, b: string): number | null {
  const pa = parts(a);
  const pb = parts(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i];
    const y = pb[i];
    if (x === undefined) return typeof y === "string" ? 1 : y === 0 ? 0 : -1;
    if (y === undefined) return typeof x === "string" ? -1 : x === 0 ? 0 : 1;
    if (x === y) continue;
    if (typeof x === "number" && typeof y === "number") return x - y;
    if (typeof x === "number") return 1; // release > pre-release
    if (typeof y === "number") return -1;
    return x < y ? -1 : 1;
  }
  return 0;
}

function inRange(version: string, v: RetireVuln): boolean {
  if (v.below) {
    const c = compareRetireVersions(version, v.below);
    if (c === null || c >= 0) return false;
  }
  if (v.atOrAbove) {
    const c = compareRetireVersions(version, v.atOrAbove);
    if (c === null || c < 0) return false;
  }
  return Boolean(v.below || v.atOrAbove);
}

const SEVERITIES = new Set(["low", "medium", "high", "critical"]);

/**
 * Libraries detected from script URLs and (optionally) script bodies, each
 * with the published vulnerabilities its version falls inside.
 */
export function matchRetire(repo: RetireRepository, scriptUrls: string[], scriptBodies: string[] = []): RetireMatch[] {
  const found = new Map<string, string>();
  const hashes = new Set(scriptBodies.map((b) => createHash("sha1").update(b).digest("hex")));

  for (const [component, def] of Object.entries(repo)) {
    if (component === "retire-example" || !def.extractors) continue;
    const ex = def.extractors;
    let version: string | null = null;
    for (const url of scriptUrls) {
      const file = url.split(/[?#]/)[0].split("/").pop() ?? "";
      version = firstVersion(ex.uri, url) ?? firstVersion(ex.filename, file);
      if (version) break;
    }
    if (!version) {
      for (const body of scriptBodies) {
        version = firstVersion(ex.filecontent, body.slice(0, 50_000));
        if (version) break;
      }
    }
    if (!version && ex.hashes) {
      for (const [hash, v] of Object.entries(ex.hashes)) {
        if (hashes.has(hash.toLowerCase())) {
          version = v;
          break;
        }
      }
    }
    if (version && !found.has(component)) found.set(component, version);
  }

  return [...found.entries()].map(([component, version]) => ({
    component,
    version,
    vulnerabilities: (repo[component].vulnerabilities ?? [])
      .filter((v) => inRange(version, v))
      .map((v) => ({
        severity: (SEVERITIES.has(v.severity ?? "") ? v.severity : "medium") as RetireMatch["vulnerabilities"][number]["severity"],
        summary: v.identifiers?.summary ?? v.identifiers?.githubID ?? "Known vulnerability",
        cveIds: (v.identifiers?.CVE ?? []).filter((c) => /^CVE-\d{4}-\d+$/i.test(c)).map((c) => c.toUpperCase()),
        below: v.below,
      })),
  }));
}

/**
 * retire.js component ids mapped to the display names findings already use,
 * so existing checkIds (`webapp.vulnerable-js-lib:<name>`) and their
 * lifecycle history carry over, and osv.ts/endOfLife.ts keep matching.
 */
export const RETIRE_DISPLAY_NAMES: Record<string, string> = {
  jquery: "jQuery",
  "moment.js": "Moment.js",
  lodash: "Lodash",
  "underscore.js": "Underscore.js",
  bootstrap: "Bootstrap",
  angularjs: "AngularJS",
  prototypejs: "Prototype.js",
};

export function displayName(component: string): string {
  return RETIRE_DISPLAY_NAMES[component] ?? component;
}

// Tolerant, ecosystem-aware version comparison, for reading OSV.dev range
// events (`introduced` / `fixed`) against an installed version.
//
// OSV.dev describes affected versions as ranges. SEMVER ranges (npm, Go,
// crates.io) compare as semantic versions. ECOSYSTEM ranges (PyPI, Maven,
// RubyGems, NuGet, Packagist) use each ecosystem's own ordering, and those
// differ in the details: PEP 440's ".dev1" sorts below "a1" and ".post1"
// above the release; Maven's "-SNAPSHOT" sits between "-rc" and the release
// and its unknown qualifiers ("-jre") sort *above* it; RubyGems' ".pre" is a
// prerelease; Composer has "-p1" patch releases. Rather than five exact
// re-implementations, this is one tokenising comparator that agrees with
// all of them on the shapes real advisories use, plus a strict SemVer 2
// comparator for the ecosystems that are SemVer.
//
// Returns null when either version can't be read at all ("dev-main", a git
// hash). Callers must treat null as "can't tell" — never as "equal" or "not
// affected".

/** Ecosystems whose versions are SemVer (NuGet is SemVer 2 with an optional fourth number). */
const SEMVER_ECOSYSTEMS = new Set(["npm", "Go", "crates.io", "NuGet"]);

type Token = { kind: "num"; value: number } | { kind: "qual"; rank: number; word: string };

// Lower rank sorts earlier. 0 is "a release", which is why "ga"/"final"/
// "release"/"stable" are dropped entirely rather than ranked.
const QUALIFIER_RANK: Record<string, number> = {
  dev: -10,
  alpha: -5,
  a: -5,
  beta: -4,
  b: -4,
  milestone: -3,
  m: -3,
  rc: -2,
  cr: -2,
  c: -2,
  pre: -2,
  preview: -2,
  snapshot: -1,
  sp: 1,
  post: 1,
  rev: 1,
  r: 1,
  pl: 1,
  patch: 1,
  p: 1,
};
const RELEASE_WORDS = new Set(["ga", "final", "release", "stable"]);

function stripPrefixAndBuild(v: string): string {
  // "v1.2.3" (Go, Composer tags) and SemVer/PEP 440 build or local
  // metadata ("+incompatible", "+build.5", "+ubuntu1") don't take part in
  // ordering.
  return v.trim().replace(/^[vV](?=\d)/, "").split("+")[0];
}

function tokenise(version: string, ecosystem: string): Token[] | null {
  let v = stripPrefixAndBuild(version);
  const tokens: Token[] = [];

  // PEP 440 epoch: "1!2.0" sorts above every epoch-0 version.
  const epoch = /^(\d+)!/.exec(v);
  tokens.push({ kind: "num", value: epoch ? Number(epoch[1]) : 0 });
  if (epoch) v = v.slice(epoch[0].length);

  const parts = v.toLowerCase().match(/\d+|[a-z]+/g);
  if (!parts || !/^\d/.test(v)) return null;

  const unknownRank = ecosystem === "Maven" ? 2 : -2.5;
  for (const p of parts) {
    if (/^\d+$/.test(p)) {
      const n = Number(p);
      if (!Number.isFinite(n)) return null;
      tokens.push({ kind: "num", value: n });
    } else if (!RELEASE_WORDS.has(p)) {
      tokens.push({ kind: "qual", rank: QUALIFIER_RANK[p] ?? unknownRank, word: p });
    }
  }

  // "1.0" == "1.0.0" == "1.0-0": drop trailing zeros at the end of every
  // run of numbers, so "1.0.0-rc1" and "1.0-rc1" read the same.
  const out: Token[] = [];
  for (let i = 0; i < tokens.length; i++) {
    out.push(tokens[i]);
    const runEnds = i === tokens.length - 1 || tokens[i + 1].kind !== "num";
    if (runEnds) {
      while (out.length > 2 && out[out.length - 1].kind === "num" && (out[out.length - 1] as { value: number }).value === 0 && out[out.length - 2].kind === "num") {
        out.pop();
      }
    }
  }
  return out;
}

function compareTokens(a: Token | undefined, b: Token | undefined): number {
  if (!a && !b) return 0;
  // A missing token is "0" against a number and "a release" against a
  // qualifier: 1.0 vs 1.0.1 → less; 1.0 vs 1.0rc1 → greater.
  if (!a) return b!.kind === "num" ? (b!.value === 0 ? 0 : -1) : 0 - b!.rank > 0 ? 1 : -1;
  if (!b) return -compareTokens(b, a);
  if (a.kind === "num" && b.kind === "num") return Math.sign(a.value - b.value);
  // A number outranks any qualifier at the same position: 1.0.1 > 1.0.post1.
  if (a.kind === "num") return 1;
  if (b.kind === "num") return -1;
  if (a.rank !== b.rank) return Math.sign(a.rank - b.rank);
  if (a.word in QUALIFIER_RANK && b.word in QUALIFIER_RANK) return 0; // rc == c == cr
  return a.word < b.word ? -1 : a.word > b.word ? 1 : 0;
}

function compareGeneric(ecosystem: string, a: string, b: string): number | null {
  const ta = tokenise(a, ecosystem);
  const tb = tokenise(b, ecosystem);
  if (!ta || !tb) return null;
  for (let i = 0; i < Math.max(ta.length, tb.length); i++) {
    const c = compareTokens(ta[i], tb[i]);
    if (c !== 0) return c;
  }
  return 0;
}

const SEMVER_RE = /^(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?$/;

function compareSemver(a: string, b: string): number | null {
  const ma = SEMVER_RE.exec(stripPrefixAndBuild(a));
  const mb = SEMVER_RE.exec(stripPrefixAndBuild(b));
  if (!ma || !mb) return null;

  const ca = ma[1].split(".").map(Number);
  const cb = mb[1].split(".").map(Number);
  for (let i = 0; i < Math.max(ca.length, cb.length); i++) {
    const d = (ca[i] ?? 0) - (cb[i] ?? 0);
    if (d !== 0) return Math.sign(d);
  }

  // SemVer 2 §11: a prerelease sorts below its release; identifiers compare
  // numerically when numeric, lexically otherwise, numeric below alphanumeric.
  const pa = ma[2];
  const pb = mb[2];
  if (!pa && !pb) return 0;
  if (!pa) return 1;
  if (!pb) return -1;
  const ia = pa.split(".");
  const ib = pb.split(".");
  for (let i = 0; i < Math.max(ia.length, ib.length); i++) {
    const x = ia[i];
    const y = ib[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) {
      const d = Number(x) - Number(y);
      if (d !== 0) return Math.sign(d);
    } else if (xn !== yn) {
      return xn ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

/**
 * Compares two versions under `ecosystem`'s ordering (an OSV.dev ecosystem
 * name: "npm", "PyPI", "Maven", ...). Negative when a < b, 0 when equal,
 * positive when a > b, null when either can't be read.
 */
export function compareEcosystemVersions(ecosystem: string, a: string, b: string): number | null {
  if (SEMVER_ECOSYSTEMS.has(ecosystem)) {
    const strict = compareSemver(a, b);
    if (strict !== null) return strict;
  }
  return compareGeneric(ecosystem, a, b);
}

/** True when `version` can be ordered at all under `ecosystem`. */
export function isComparableVersion(ecosystem: string, version: string): boolean {
  return compareEcosystemVersions(ecosystem, version, version) !== null;
}

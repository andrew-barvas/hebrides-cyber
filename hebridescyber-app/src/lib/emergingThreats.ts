// Emerging-threat alerts — the pure half (no I/O; see emergingThreatAlerts.ts
// for the lookups, the ledger and the notifications).
//
// When CISA adds a CVE to its Known Exploited Vulnerabilities catalog, we
// look up which product versions it affects and compare them with the
// technology and version each customer's latest scan saw. Intruder sells the
// same idea as "emerging threat scans"; this does it from data we already
// hold, without re-scanning anyone.
//
// WHERE THE VERSION RANGES COME FROM
//   - NVD's CVE API 2.0 configurations: CPE match criteria with
//     versionStart/End Including/Excluding, or an exact version in the CPE.
//     Our technology names map to CPE vendor:product through
//     softwareCveDb.ts's NVD_CPE_BY_NAME (each entry checked against a real
//     NVD record).
//   - OSV.dev, for client-side libraries published on npm: the CVE's GitHub
//     advisory (GHSA) carries npm semver ranges. When OSV has npm data for a
//     CVE, it is authoritative for our npm-mapped libraries and NVD is not
//     consulted for them. Verified against live data: NVD files Angular's
//     CVE-2021-4231 under angularjs:angularjs "before 11.0.5", which would
//     flag every AngularJS 1.x site; the GHSA lists only @angular/core.
//
// EVIDENCE TIERS (never alert on a name match alone)
//   - "affected": the detected version is inside a vulnerable range.
//   - "possibly_affected": the product was detected but we can't place it —
//     no version visible, only a partial one ("6.4" against a 6.4.3 fix),
//     a distribution-packaged version (vendors backport fixes without
//     changing the number), or a range NVD only lists as vulnerable in
//     combination with something we can't see from outside (operator AND,
//     e.g. CVE-2024-4577 is PHP *on Windows*).
//   - A range whose bounds use a different version scheme (nginx Plus "r22")
//     can't be compared, so it counts as no evidence either way.
import type { KevIndex } from "./scanners/threatIntel";
import { NVD_CPE_BY_NAME } from "./scanners/softwareCveDb";
import { npmPackageNameFor } from "./scanners/osv";
import type { TechObservation } from "./scanners/techInventory";

/** KEV additions this recent are checked (the job runs every 6 hours). */
export const KEV_LOOKBACK_DAYS = 3;
/** Only scans this recent count as evidence of what a site runs today. */
export const SCAN_LOOKBACK_DAYS = 30;

const DAY_MS = 24 * 60 * 60 * 1000;
const CVE_RE = /^CVE-\d{4}-\d+$/;

// ---- Recent KEV additions -----------------------------------------------------

export type KevAddition = {
  cveId: string;
  vendorProject: string | null;
  product: string | null;
  vulnerabilityName: string | null;
  /** YYYY-MM-DD */
  dateAdded: string;
  ransomware: boolean;
};

/**
 * Catalog entries CISA added on or after the UTC day `days` days before
 * `now`. Entries without a readable dateAdded are skipped — there's no way
 * to know they're new.
 */
export function recentKevAdditions(kev: KevIndex, now: Date, days: number = KEV_LOOKBACK_DAYS): KevAddition[] {
  const cutoff = new Date(now.getTime() - days * DAY_MS).toISOString().slice(0, 10);
  const out: KevAddition[] = [];
  for (const [cveId, entry] of kev) {
    if (!entry.dateAdded || entry.dateAdded < cutoff || !CVE_RE.test(cveId)) continue;
    out.push({
      cveId,
      vendorProject: entry.vendorProject ?? null,
      product: entry.product ?? null,
      vulnerabilityName: entry.vulnerabilityName ?? null,
      dateAdded: entry.dateAdded,
      ransomware: entry.ransomware,
    });
  }
  return out.sort((a, b) => (a.dateAdded === b.dateAdded ? a.cveId.localeCompare(b.cveId) : b.dateAdded.localeCompare(a.dateAdded)));
}

// ---- Versions -----------------------------------------------------------------

export type ParsedVersion = { nums: number[]; pre: string | null };

/**
 * "2.4.49" → [2,4,49]; "11.1.0-next.0" → [11,1,0] + prerelease "next.0".
 * Anything else ("r22", "1.0.2k", "3.8m0") is a scheme we can't order, → null.
 */
export function parseVersion(raw: string): ParsedVersion | null {
  const m = /^v?(\d+(?:\.\d+)*)(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?(?:\+[0-9A-Za-z.-]+)?$/.exec(raw.trim());
  if (!m) return null;
  const nums = m[1].split(".").map(Number);
  if (nums.some((n) => !Number.isSafeInteger(n))) return null;
  return { nums, pre: m[2] ?? null };
}

/**
 * How a detected version compares with a range bound. A detected version can
 * be shorter than the bound ("6.4" from a generator tag against a 6.4.3
 * fix): it then stands for any 6.4.x, so the answer can be "ge" (6.4.x is at
 * least 6.4.0, maybe equal) or "unknown" (6.4.x could sit either side of
 * 6.4.3).
 */
export type VersionComparison = "lt" | "eq" | "gt" | "ge" | "unknown";

export function compareToBound(detected: ParsedVersion, bound: ParsedVersion): VersionComparison {
  const d = detected.nums;
  const b = bound.nums;
  for (let i = 0; i < Math.min(d.length, b.length); i++) {
    if (d[i] < b[i]) return "lt";
    if (d[i] > b[i]) return "gt";
  }
  if (d.length >= b.length) {
    if (d.slice(b.length).some((n) => n > 0)) return "gt";
    if (detected.pre === bound.pre) return "eq";
    if (detected.pre === null) return "gt"; // 3.0.0 is after 3.0.0-beta.1
    if (bound.pre === null) return "lt";
    return "unknown";
  }
  if (detected.pre !== null) return "unknown";
  const rest = b.slice(d.length);
  if (rest.every((n) => n === 0)) return bound.pre === null ? "ge" : "gt";
  return "unknown";
}

// ---- Ranges -------------------------------------------------------------------

export type VersionRange = {
  source: "nvd" | "osv";
  /** One vulnerable version (an NVD CPE naming a version instead of "*"). */
  exact?: string;
  startIncluding?: string;
  startExcluding?: string;
  endIncluding?: string;
  endExcluding?: string;
  /** NVD lists this only as vulnerable together with something else (AND). */
  conditional?: boolean;
};

/** "in" / "out" of the range, "unknown" when a partial version straddles it. */
export type RangeVerdict = "in" | "out" | "unknown";

type BoundKind = "exact" | "startIncluding" | "startExcluding" | "endIncluding" | "endExcluding";

function boundVerdict(kind: BoundKind, cmp: VersionComparison): RangeVerdict {
  switch (kind) {
    case "exact":
      return cmp === "eq" ? "in" : cmp === "lt" || cmp === "gt" ? "out" : "unknown";
    case "startIncluding":
      return cmp === "lt" ? "out" : cmp === "unknown" ? "unknown" : "in";
    case "startExcluding":
      return cmp === "gt" ? "in" : cmp === "eq" || cmp === "lt" ? "out" : "unknown";
    case "endIncluding":
      return cmp === "lt" || cmp === "eq" ? "in" : cmp === "gt" ? "out" : "unknown";
    case "endExcluding":
      return cmp === "lt" ? "in" : cmp === "unknown" ? "unknown" : "out";
  }
}

/**
 * Where `version` sits against `range`. Null when it can't be placed at all —
 * the detected version or a bound uses a scheme we can't order — which the
 * caller must treat as no evidence, never as "in".
 */
export function versionInRange(version: string, range: VersionRange): RangeVerdict | null {
  const detected = parseVersion(version);
  if (!detected) return null;
  let verdict: RangeVerdict = "in";
  for (const kind of ["exact", "startIncluding", "startExcluding", "endIncluding", "endExcluding"] as const) {
    const raw = range[kind];
    if (raw === undefined) continue;
    const bound = parseVersion(raw);
    if (!bound) return null;
    const v = boundVerdict(kind, compareToBound(detected, bound));
    if (v === "out") return "out";
    if (v === "unknown") verdict = "unknown";
  }
  return verdict;
}

// ---- NVD configurations -----------------------------------------------------------

type NvdCpeMatch = {
  vulnerable?: boolean;
  criteria?: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
};
type NvdNode = { operator?: string; negate?: boolean; cpeMatch?: NvdCpeMatch[] };
type NvdConfiguration = { operator?: string; negate?: boolean; nodes?: NvdNode[] };
/** The `cve` object of an NVD CVE API 2.0 response (only what we read). */
export type NvdCveRecord = { id?: string; vulnStatus?: string; configurations?: NvdConfiguration[] };

/** Splits a CPE 2.3 formatted string on unescaped colons; null if malformed. */
export function splitCpe(cpe: string): string[] | null {
  const parts: string[] = [];
  let current = "";
  for (let i = 0; i < cpe.length; i++) {
    const ch = cpe[i];
    if (ch === "\\" && i + 1 < cpe.length) {
      current += ch + cpe[i + 1];
      i++;
    } else if (ch === ":") {
      parts.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  parts.push(current);
  return parts.length === 13 && parts[0] === "cpe" && parts[1] === "2.3" ? parts : null;
}

const TECH_BY_CPE = new Map(Object.entries(NVD_CPE_BY_NAME).map(([tech, c]) => [`${c.vendor}:${c.product}`, tech]));

/** NVD's ranges for each of our technologies the CVE's configurations name. */
export function nvdRangesByTech(cve: NvdCveRecord | null): Map<string, VersionRange[]> {
  const out = new Map<string, VersionRange[]>();
  for (const config of cve?.configurations ?? []) {
    const nodes = config.nodes ?? [];
    const configConditional = (config.operator === "AND" && nodes.length > 1) || config.negate === true;
    for (const node of nodes) {
      if (node.negate) continue; // describes what is NOT affected
      const matches = node.cpeMatch ?? [];
      const conditional = configConditional || (node.operator === "AND" && matches.length > 1);
      for (const m of matches) {
        if (m.vulnerable !== true || typeof m.criteria !== "string") continue;
        const parts = splitCpe(m.criteria);
        if (!parts || parts[2] !== "a") continue;
        const tech = TECH_BY_CPE.get(`${parts[3]}:${parts[4]}`);
        if (!tech) continue;
        const [version, update] = [parts[5], parts[6]];
        // A named update ("rc1", "next0", "beta") is a pre-release; our
        // detected versions never are, so the entry can't be ours.
        if (update !== "*" && update !== "-") continue;
        if (version === "-" || version === "") continue;
        const range: VersionRange = { source: "nvd" };
        if (version !== "*") range.exact = version.replace(/\\(.)/g, "$1");
        else {
          if (m.versionStartIncluding) range.startIncluding = m.versionStartIncluding;
          if (m.versionStartExcluding) range.startExcluding = m.versionStartExcluding;
          if (m.versionEndIncluding) range.endIncluding = m.versionEndIncluding;
          if (m.versionEndExcluding) range.endExcluding = m.versionEndExcluding;
        }
        if (conditional) range.conditional = true;
        const list = out.get(tech) ?? [];
        list.push(range);
        out.set(tech, list);
      }
    }
  }
  return out;
}

// ---- OSV (npm) ------------------------------------------------------------------

type OsvEvent = { introduced?: string; fixed?: string; last_affected?: string; limit?: string };
type OsvAffected = {
  package?: { name?: string; ecosystem?: string };
  ranges?: Array<{ type?: string; events?: OsvEvent[] }>;
  versions?: string[];
};
/** An OSV.dev vulnerability record (only what we read). */
export type OsvVulnRecord = { id?: string; aliases?: string[]; affected?: OsvAffected[] };

/** Our technology name → its npm package, for the OSV lookup. */
export function npmPackageForTech(tech: string): string | null {
  // fingerprint.ts's "Angular" is Angular 2+ (read from ng-version), which
  // npm publishes as @angular/*; osv.ts's map covers webapp.ts's libraries.
  if (tech === "Angular") return "@angular/core";
  return npmPackageNameFor(tech);
}

/** Every npm package any of these records lists as affected. */
export function osvNpmPackages(records: OsvVulnRecord[]): Set<string> {
  const names = new Set<string>();
  for (const r of records) {
    for (const a of r.affected ?? []) {
      if (a.package?.ecosystem === "npm" && a.package.name) names.add(a.package.name);
    }
  }
  return names;
}

/** OSV's affected ranges for one npm package, as VersionRanges. */
export function osvRangesForPackage(records: OsvVulnRecord[], npmPackage: string): VersionRange[] {
  const out: VersionRange[] = [];
  for (const r of records) {
    for (const a of r.affected ?? []) {
      if (a.package?.ecosystem !== "npm" || a.package.name !== npmPackage) continue;
      const ranges = (a.ranges ?? []).filter((x) => x.type === "SEMVER" || x.type === "ECOSYSTEM");
      for (const range of ranges) {
        let start: string | null = null;
        let open = false;
        const close = (end: Partial<VersionRange>) => {
          out.push({ source: "osv", ...(start ? { startIncluding: start } : {}), ...end });
          open = false;
        };
        for (const e of range.events ?? []) {
          if (e.introduced !== undefined) {
            start = e.introduced === "0" ? null : e.introduced;
            open = true;
          } else if (e.fixed !== undefined) close({ endExcluding: e.fixed });
          else if (e.last_affected !== undefined) close({ endIncluding: e.last_affected });
          else if (e.limit !== undefined) close({ endExcluding: e.limit });
        }
        if (open) close({}); // introduced with no fix yet: still affected
      }
      // Explicit version lists only matter when there are no ranges to read.
      if (ranges.length === 0) for (const v of a.versions ?? []) out.push({ source: "osv", exact: v });
    }
  }
  return out;
}

// ---- Per-CVE affected technologies -------------------------------------------------

export type CveTechRanges = { cveId: string; byTech: Map<string, VersionRange[]> };

const KNOWN_TECHS = [...new Set([...Object.keys(NVD_CPE_BY_NAME), "Angular", "AngularJS", "jQuery", "Bootstrap", "Lodash", "Moment.js", "Underscore.js"])];

/**
 * Which of our technologies the CVE affects, and in which versions. For an
 * npm-mapped library, OSV's npm data wins whenever OSV has npm data for the
 * CVE at all — a package missing from it is a reviewed "not this package",
 * not a gap to fill from NVD (see the header for the Angular example).
 */
export function buildCveTechRanges(cveId: string, nvd: NvdCveRecord | null, osv: OsvVulnRecord[]): CveTechRanges {
  const fromNvd = nvdRangesByTech(nvd);
  const osvHasNpm = osvNpmPackages(osv).size > 0;
  const byTech = new Map<string, VersionRange[]>();
  for (const tech of KNOWN_TECHS) {
    const npm = npmPackageForTech(tech);
    const ranges = npm && osvHasNpm ? osvRangesForPackage(osv, npm) : fromNvd.get(tech) ?? [];
    if (ranges.length > 0) byTech.set(tech, ranges);
  }
  return { cveId, byTech };
}

// ---- Matching -------------------------------------------------------------------

export type EvidenceTier = "affected" | "possibly_affected";
export type MatchReason = "version_in_range" | "version_unknown" | "partial_version" | "distro_packaged" | "platform_specific";
export type TechAssessment = { tier: EvidenceTier; reason: MatchReason };

/**
 * Whether one detected technology is covered by a CVE's ranges for it. Null
 * when the evidence says it isn't, or says nothing.
 */
export function assessObservation(obs: Pick<TechObservation, "version" | "packagedBy">, ranges: VersionRange[]): TechAssessment | null {
  if (ranges.length === 0) return null;
  if (!obs.version || !parseVersion(obs.version)) return { tier: "possibly_affected", reason: "version_unknown" };

  let definite = false;
  let conditional = false;
  let straddles = false;
  for (const range of ranges) {
    const verdict = versionInRange(obs.version, range);
    if (verdict === "in" && !range.conditional) definite = true;
    else if (verdict === "in" || (verdict === "unknown" && range.conditional)) conditional = true;
    else if (verdict === "unknown") straddles = true;
  }
  if (!definite && !conditional && !straddles) return null;
  if (obs.packagedBy) return { tier: "possibly_affected", reason: "distro_packaged" };
  if (definite) return { tier: "affected", reason: "version_in_range" };
  return { tier: "possibly_affected", reason: conditional ? "platform_specific" : "partial_version" };
}

export const PRODUCT_LABELS: Record<string, string> = {
  Apache: "Apache HTTP Server",
  Nginx: "nginx",
  IIS: "Microsoft IIS",
};
export const productLabel = (tech: string): string => PRODUCT_LABELS[tech] ?? tech;

export type ThreatMatch = {
  cveId: string;
  tech: string;
  /** Display name for alerts and the ledger's `product` column. */
  product: string;
  detectedVersion: string | null;
  packagedBy: string | null;
  tier: EvidenceTier;
  reason: MatchReason;
};

/**
 * One match per CVE per host — the strongest evidence among the host's
 * technologies (a jQuery CVE can cover both jQuery and the Drupal release
 * that bundles it).
 */
export function matchHost(inventory: TechObservation[], cves: CveTechRanges[]): ThreatMatch[] {
  const out: ThreatMatch[] = [];
  for (const cve of cves) {
    let best: ThreatMatch | null = null;
    for (const obs of inventory) {
      const ranges = cve.byTech.get(obs.tech);
      if (!ranges) continue;
      const a = assessObservation(obs, ranges);
      if (!a) continue;
      if (!best || (best.tier === "possibly_affected" && a.tier === "affected")) {
        best = {
          cveId: cve.cveId,
          tech: obs.tech,
          product: productLabel(obs.tech),
          detectedVersion: obs.version,
          packagedBy: obs.packagedBy,
          tier: a.tier,
          reason: a.reason,
        };
      }
    }
    if (best) out.push(best);
  }
  return out;
}

// ---- Scans ----------------------------------------------------------------------

export type ScanCandidate = { id: string; target_url: string; created_at: string };

export function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase() || null;
  } catch {
    return null;
  }
}

/**
 * The most recent scan per hostname — the same hostname matching
 * scanReport.ts's findPreviousFindings uses, since there is no host column
 * and target_url differs between scans of one site (path, slash, case).
 */
export function latestScanPerHost(scans: ScanCandidate[]): Map<string, ScanCandidate> {
  const latest = new Map<string, ScanCandidate>();
  for (const scan of scans) {
    const host = hostOf(scan.target_url);
    if (!host) continue;
    const current = latest.get(host);
    if (!current || Date.parse(scan.created_at) > Date.parse(current.created_at)) latest.set(host, scan);
  }
  return latest;
}

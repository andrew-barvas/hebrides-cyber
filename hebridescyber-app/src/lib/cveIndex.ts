// Local CPE → CVE index: the lookup half. Built nightly from NVD's CVE API 2.0
// by cveIndexFeed.ts (src/scripts/sync-cve-index.ts) into Postgres
// (sql/migrations/069_cve_cpe_index.sql), and read here — never NVD itself, so
// a scan makes no rate-limited NVD calls however many services it finds
// (softwareCveDb.ts's per-scan NVD lookups already hit that limit).
//
// THE API (what P1-5's device patch audit reuses)
//
//   const index = createCveIndex(supabaseCveIndexStore(supabaseAdmin));
//   await index.lookup({ cpe: "cpe:/a:openbsd:openssh:8.9p1" });
//   await index.lookup({ vendor: "oracle", product: "mysql", version: "8.0.35" });
//
// `lookup` answers one of:
//   - "checked": the version was compared against every indexed criterion for
//     that vendor:product. `matches` are the CVEs whose version range contains
//     it (empty = genuinely none indexed); `undetermined` are CVEs whose range
//     the version can't be placed against (a partial version, a pre-release
//     bound) — neither a match nor a clean result.
//   - "version_unknown": no version to compare. Never a CVE.
//   - "unordered_version": a version in a scheme we can't order ("r22").
//   - "error": the index is missing, never finished its first build, is stale,
//     or the read failed. Never a clean answer (CLAUDE.md rule 7).
//
// EVIDENCE RULES
//   - Only version-bounded criteria count: an exact version in the CPE, or at
//     least one versionStart/End bound. A criterion naming every version
//     ("*", no bounds) is not stored at all — a product-name match alone is
//     not evidence.
//   - A criterion NVD lists as vulnerable only together with something else
//     (an AND configuration: "this app on that OS") comes back with
//     `conditional: true`. Callers decide; serviceCve.ts does not report them.
//   - Versions compare token by token ("8.9p1" → 8, 9, p, 1). OpenSSH's
//     portable suffix orders after its base release (9.8 < 9.8p1); any other
//     letter run (rc, beta) against a number is "can't tell", never a match.
//   - Distribution backports (Ubuntu's 8.9p1-3ubuntu0.10 has fixes 8.9p1
//     upstream doesn't) are not this module's concern: it answers for the
//     upstream version it is given, and the caller says so.
import type { SupabaseClient } from "@supabase/supabase-js";

/** The index must have synced this recently to be trusted (the job is nightly). */
export const CVE_INDEX_MAX_AGE_DAYS = 7;

const DAY_MS = 24 * 60 * 60 * 1000;
const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

// ---- CPE names ------------------------------------------------------------------

export type CpePart = "a" | "o" | "h";
export type CpeName = { part: CpePart; vendor: string; product: string; version: string | null };

function cpeField(raw: string | undefined): string | null {
  if (raw === undefined || raw === "" || raw === "*" || raw === "-") return null;
  return raw;
}

/** Lowercased, escapes removed: how cve_cpe_matches stores vendor and product. */
export function normaliseCpeComponent(raw: string): string {
  return raw.replace(/\\(.)/g, "$1").toLowerCase();
}

/** Splits a CPE 2.3 formatted string on unescaped colons (escapes kept). */
export function splitCpe23(cpe: string): string[] {
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
  return parts;
}

/**
 * Parses a CPE 2.2 URI (what nmap emits: "cpe:/a:openbsd:openssh:8.9p1") or a
 * CPE 2.3 formatted string (what NVD uses). The update field, when it names
 * one, is folded into the version ("4.4" + "p1" → "4.4p1"), matching how the
 * feed stores exact versions. Null when it isn't a CPE.
 */
export function parseCpe(cpe: string): CpeName | null {
  const s = cpe.trim();
  let fields: string[];
  if (s.startsWith("cpe:2.3:")) {
    fields = splitCpe23(s).slice(2);
  } else if (s.startsWith("cpe:/")) {
    try {
      fields = s.slice(5).split(":").map((f) => decodeURIComponent(f));
    } catch {
      return null;
    }
  } else {
    return null;
  }
  const [part, vendor, product, version, update] = fields;
  if (part !== "a" && part !== "o" && part !== "h") return null;
  if (!cpeField(vendor) || !cpeField(product)) return null;
  const v = cpeField(version);
  const u = cpeField(update);
  return {
    part,
    vendor: normaliseCpeComponent(vendor),
    product: normaliseCpeComponent(product),
    version: v ? normaliseCpeComponent(v) + (u ? normaliseCpeComponent(u) : "") : null,
  };
}

/**
 * vendor:product names nmap's service database uses that NVD files under a
 * different name. Each was checked against a real NVD record: NVD moved nginx
 * to F5 (CVE-2021-23017 reads f5:nginx), MySQL 8 CVEs read oracle:mysql
 * (CVE-2024-20963), and vsftpd is vsftpd_project:vsftpd (CVE-2011-2523).
 * The original name is still queried too — older CVEs stay under it.
 */
export const CPE_ALIASES: Record<string, string[]> = {
  "igor_sysoev:nginx": ["f5:nginx"],
  "nginx:nginx": ["f5:nginx"],
  "mysql:mysql": ["oracle:mysql"],
  "vsftpd:vsftpd": ["vsftpd_project:vsftpd"],
};

// ---- Versions ------------------------------------------------------------------

type Token = number | string;

function versionTokens(raw: string): Token[] | null {
  const s = raw.trim().toLowerCase();
  if (!/^\d/.test(s) || !/^[0-9a-z._+~-]+$/.test(s)) return null;
  const out: Token[] = [];
  for (const m of s.matchAll(/\d+|[a-z]+/g)) {
    if (/^\d/.test(m[0])) {
      const n = Number(m[0]);
      if (!Number.isSafeInteger(n)) return null;
      out.push(n);
    } else {
      out.push(m[0]);
    }
  }
  return out;
}

/** True when `raw` is a version this module can order at all. */
export function isOrderableVersion(raw: string): boolean {
  return versionTokens(raw) !== null;
}

export type VersionComparison = "lt" | "eq" | "gt" | "unknown";

/**
 * Compares a detected version with a bound. Beyond the shared prefix: trailing
 * zeros are equal (2.4 = 2.4.0); a portable suffix is later (9.8p1 > 9.8);
 * extra numbers on the detected side are later (2.4.49 > 2.4); extra numbers
 * on the bound side mean a partial detected version ("2.4" against 2.4.49),
 * which can't be placed; any other letters are "unknown".
 */
export function compareVersions(detected: string, bound: string): VersionComparison {
  const a = versionTokens(detected);
  const b = versionTokens(bound);
  if (!a || !b) return "unknown";
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i];
    const y = b[i];
    if (typeof x === "number" && typeof y === "number") {
      if (x !== y) return x < y ? "lt" : "gt";
    } else if (typeof x === "string" && typeof y === "string") {
      // Single letters order (OpenSSL's 1.0.2k < 1.0.2u); words don't.
      if (x === y) continue;
      return x.length === 1 && y.length === 1 ? (x < y ? "lt" : "gt") : "unknown";
    } else {
      return "unknown";
    }
  }
  const rest = (a.length > b.length ? a : b).slice(n);
  if (rest.length === 0 || rest.every((t) => t === 0)) return "eq";
  const detectedLonger = a.length > b.length;
  if (rest[0] === "p" && (rest.length === 1 || typeof rest[1] === "number")) return detectedLonger ? "gt" : "lt";
  if (typeof rest[0] === "number") return detectedLonger ? "gt" : "unknown";
  return "unknown";
}

/** "8.9p1" → "8.9": for a criterion that names a version with any update. */
function withoutPortableSuffix(version: string): string {
  return version.replace(/p\d+$/i, "");
}

// ---- Index rows ---------------------------------------------------------------

/** One row of cve_cpe_matches: a vulnerable, version-bounded CPE criterion. */
export type CveMatchRow = {
  cve_id: string;
  part: CpePart;
  vendor: string;
  product: string;
  exact_version: string | null;
  /** The criterion names exact_version with update "*": 7.4 covers 7.4p1. */
  any_update: boolean;
  start_including: string | null;
  start_excluding: string | null;
  end_including: string | null;
  end_excluding: string | null;
  conditional: boolean;
  /** NVD's criterion as written — the evidence a finding cites. */
  criteria: string;
};

export type CveRecordRow = {
  cve_id: string;
  cvss_score: number | null;
  cvss_version: string | null;
  cvss_vector: string | null;
  summary: string | null;
  published_at: string | null;
  last_modified_at: string;
};

export type CveIndexState = {
  backfill_completed_at: string | null;
  last_success_at: string | null;
  last_modified_through: string | null;
  cve_count: number | null;
};

/** Whether a row carries a version bound at all; unbounded rows are never evidence. */
export function isVersionBounded(row: Pick<CveMatchRow, "exact_version" | "start_including" | "start_excluding" | "end_including" | "end_excluding">): boolean {
  return Boolean(row.exact_version || row.start_including || row.start_excluding || row.end_including || row.end_excluding);
}

export type RangeVerdict = "in" | "out" | "unknown";

/** Where `version` sits against one criterion. */
export function versionInCriterion(version: string, row: CveMatchRow): RangeVerdict {
  if (!isVersionBounded(row)) return "out";
  if (row.exact_version) {
    const cmp = compareVersions(row.any_update ? withoutPortableSuffix(version) : version, row.exact_version);
    return cmp === "eq" ? "in" : cmp === "unknown" ? "unknown" : "out";
  }
  let verdict: RangeVerdict = "in";
  const check = (bound: string | null, ok: (c: VersionComparison) => boolean) => {
    if (!bound || verdict === "out") return;
    const cmp = compareVersions(version, bound);
    if (cmp === "unknown") verdict = "unknown";
    else if (!ok(cmp)) verdict = "out";
  };
  check(row.start_including, (c) => c !== "lt");
  check(row.start_excluding, (c) => c === "gt");
  check(row.end_including, (c) => c !== "gt");
  check(row.end_excluding, (c) => c === "lt");
  return verdict;
}

/** Human form of a criterion's range, for finding evidence: ">= 8.6, <= 9.8". */
export function describeCriterion(row: CveMatchRow): string {
  if (row.exact_version) return row.any_update ? `${row.exact_version} (any update)` : row.exact_version;
  const parts: string[] = [];
  if (row.start_including) parts.push(`>= ${row.start_including}`);
  if (row.start_excluding) parts.push(`> ${row.start_excluding}`);
  if (row.end_including) parts.push(`<= ${row.end_including}`);
  if (row.end_excluding) parts.push(`< ${row.end_excluding}`);
  return parts.join(", ");
}

export type CveMatch = {
  cveId: string;
  cvssScore: number | null;
  cvssVersion: string | null;
  cvssVector: string | null;
  summary: string | null;
  publishedAt: string | null;
  /** NVD's CPE criterion that matched, as written. */
  matchedCriteria: string;
  /** The criterion's version range, human-readable. */
  range: string;
  /** NVD lists it as vulnerable only in combination with something else. */
  conditional: boolean;
};

/**
 * Pure: which CVEs `version` is inside the range of. A CVE matches when any
 * of its criteria is "in"; it is undetermined when none is "in" but one can't
 * be placed. An unconditional criterion wins over a conditional one.
 */
export function matchCriteria(version: string, rows: CveMatchRow[]): { matched: Map<string, CveMatchRow>; undetermined: Set<string> } {
  const matched = new Map<string, CveMatchRow>();
  const undetermined = new Set<string>();
  for (const row of rows) {
    const verdict = versionInCriterion(version, row);
    if (verdict === "in") {
      const seen = matched.get(row.cve_id);
      if (!seen || (seen.conditional && !row.conditional)) matched.set(row.cve_id, row);
    } else if (verdict === "unknown") {
      undetermined.add(row.cve_id);
    }
  }
  for (const id of matched.keys()) undetermined.delete(id);
  return { matched, undetermined };
}

// ---- Lookup ------------------------------------------------------------------------

export type CveQuery =
  /** A CPE (2.2 URI or 2.3); `version` overrides the CPE's own when given. */
  | { cpe: string; version?: string | null }
  | { vendor: string; product: string; version: string | null; part?: CpePart };

export type CveLookupResult =
  | {
      status: "checked";
      /** The CPE that was looked up, in 2.3 form with the compared version. */
      cpe: string;
      version: string;
      matches: CveMatch[];
      undetermined: string[];
      /** NVD's last-modified time the index is current to. */
      indexedThrough: string | null;
    }
  | { status: "version_unknown"; cpe: string }
  | { status: "unordered_version"; cpe: string; version: string }
  | { status: "error"; note: string };

/** Where the index lives. Each method throws on a failed read. */
export interface CveIndexStore {
  readState(): Promise<CveIndexState | null>;
  /** Every stored criterion for one vendor:product (all parts). */
  readMatches(vendor: string, product: string): Promise<CveMatchRow[]>;
  readRecords(cveIds: string[]): Promise<CveRecordRow[]>;
}

export type CveIndex = {
  lookup(query: CveQuery): Promise<CveLookupResult>;
};

/** Null when the index is usable; otherwise why it isn't. */
export function indexUnusableReason(state: CveIndexState | null, now: Date, maxAgeDays: number = CVE_INDEX_MAX_AGE_DAYS): string | null {
  if (!state) return "CVE index has never been built (run the CVE index sync job).";
  if (!state.backfill_completed_at) return "CVE index's first full build has not finished.";
  const last = state.last_success_at ? Date.parse(state.last_success_at) : NaN;
  if (!Number.isFinite(last)) return "CVE index has no successful sync recorded.";
  const ageDays = (now.getTime() - last) / DAY_MS;
  if (ageDays > maxAgeDays) return `CVE index is stale: last synced ${Math.floor(ageDays)} days ago (limit ${maxAgeDays}).`;
  return null;
}

function toCpe23(name: Omit<CpeName, "version">, version: string | null): string {
  const esc = (s: string) => s.replace(/([^a-z0-9._-])/gi, "\\$1");
  return `cpe:2.3:${name.part}:${esc(name.vendor)}:${esc(name.product)}:${version ? esc(version) : "*"}:*:*:*:*:*:*:*`;
}

/**
 * The lookup API. One instance per scan (or per inventory upload): the index
 * state is read once, and each vendor:product's criteria once, then reused.
 */
export function createCveIndex(store: CveIndexStore, options: { now?: Date; maxAgeDays?: number } = {}): CveIndex {
  const now = options.now ?? new Date();
  let statePromise: Promise<{ state: CveIndexState | null; unusable: string | null }> | null = null;
  const rowsCache = new Map<string, Promise<CveMatchRow[]>>();
  const recordCache = new Map<string, CveRecordRow>();

  const loadState = () => {
    statePromise ??= store.readState().then((state) => ({ state, unusable: indexUnusableReason(state, now, options.maxAgeDays) }));
    return statePromise;
  };
  const loadRows = (vendor: string, product: string) => {
    const key = `${vendor}:${product}`;
    let p = rowsCache.get(key);
    if (!p) {
      p = store.readMatches(vendor, product);
      rowsCache.set(key, p);
    }
    return p;
  };

  return {
    async lookup(query) {
      let name: CpeName | null;
      if ("cpe" in query) {
        name = parseCpe(query.cpe);
        if (!name) return { status: "error", note: `Not a CPE name: ${query.cpe}` };
        if (query.version !== undefined) name = { ...name, version: query.version ? query.version.trim().toLowerCase() : null };
      } else {
        name = {
          part: query.part ?? "a",
          vendor: normaliseCpeComponent(query.vendor),
          product: normaliseCpeComponent(query.product),
          version: query.version ? query.version.trim().toLowerCase() : null,
        };
      }
      const cpe = toCpe23(name, name.version);
      if (!name.version) return { status: "version_unknown", cpe };
      if (!isOrderableVersion(name.version)) return { status: "unordered_version", cpe, version: name.version };

      try {
        const { state, unusable } = await loadState();
        if (unusable) return { status: "error", note: unusable };

        const keys = [`${name.vendor}:${name.product}`, ...(CPE_ALIASES[`${name.vendor}:${name.product}`] ?? [])];
        const rowSets = await Promise.all(
          keys.map((k) => {
            const [vendor, product] = k.split(":");
            return loadRows(vendor, product);
          })
        );
        const part = name.part;
        const rows = rowSets.flat().filter((r) => r.part === part && CVE_RE.test(r.cve_id));
        const { matched, undetermined } = matchCriteria(name.version, rows);

        const missing = [...matched.keys()].filter((id) => !recordCache.has(id));
        if (missing.length > 0) for (const rec of await store.readRecords(missing)) recordCache.set(rec.cve_id, rec);

        const matches: CveMatch[] = [...matched.entries()].map(([cveId, row]) => {
          const rec = recordCache.get(cveId);
          return {
            cveId,
            cvssScore: rec?.cvss_score ?? null,
            cvssVersion: rec?.cvss_version ?? null,
            cvssVector: rec?.cvss_vector ?? null,
            summary: rec?.summary ?? null,
            publishedAt: rec?.published_at ?? null,
            matchedCriteria: row.criteria,
            range: describeCriterion(row),
            conditional: row.conditional,
          };
        });
        matches.sort((a, b) => (b.cvssScore ?? -1) - (a.cvssScore ?? -1) || a.cveId.localeCompare(b.cveId));
        return {
          status: "checked",
          cpe,
          version: name.version,
          matches,
          undetermined: [...undetermined].sort(),
          indexedThrough: state?.last_modified_through ?? null,
        };
      } catch (err) {
        return { status: "error", note: `CVE index read failed: ${(err as Error).message}` };
      }
    },
  };
}

// ---- Postgres store -------------------------------------------------------------------

const MATCH_COLUMNS =
  "cve_id, part, vendor, product, exact_version, any_update, start_including, start_excluding, end_including, end_excluding, conditional, criteria";
const RECORD_COLUMNS = "cve_id, cvss_score, cvss_version, cvss_vector, summary, published_at, last_modified_at";
/** PostgREST's default max-rows; read in pages of this size. */
const PAGE = 1000;
/** Keep `in.(…)` filters well inside URL limits. */
const ID_CHUNK = 150;

/**
 * The index in Postgres (migration 069), read with the service role — the
 * tables have RLS on and no client policy. Before 069 is applied every read
 * fails, which `lookup` reports as "error", never as "no CVEs".
 */
export function supabaseCveIndexStore(client: SupabaseClient): CveIndexStore {
  return {
    async readState() {
      const { data, error } = await client
        .from("cve_index_state")
        .select("backfill_completed_at, last_success_at, last_modified_through, cve_count")
        .eq("id", true)
        .maybeSingle();
      if (error) throw new Error(error.message);
      return (data as CveIndexState | null) ?? null;
    },
    async readMatches(vendor, product) {
      const rows: CveMatchRow[] = [];
      for (let from = 0; ; from += PAGE) {
        const { data, error } = await client
          .from("cve_cpe_matches")
          .select(MATCH_COLUMNS)
          .eq("vendor", vendor)
          .eq("product", product)
          .order("id", { ascending: true })
          .range(from, from + PAGE - 1);
        if (error) throw new Error(error.message);
        const page = (data ?? []) as CveMatchRow[];
        rows.push(...page);
        if (page.length < PAGE) return rows;
      }
    },
    async readRecords(cveIds) {
      const out: CveRecordRow[] = [];
      for (let i = 0; i < cveIds.length; i += ID_CHUNK) {
        const { data, error } = await client.from("cve_records").select(RECORD_COLUMNS).in("cve_id", cveIds.slice(i, i + ID_CHUNK));
        if (error) throw new Error(error.message);
        for (const r of (data ?? []) as CveRecordRow[]) out.push({ ...r, cvss_score: r.cvss_score === null ? null : Number(r.cvss_score) });
      }
      return out;
    },
  };
}

// ---- In-memory store ---------------------------------------------------------------------

/**
 * A store over rows already in memory: for tests, and for callers that load a
 * slice of the index themselves. Same contract as the Postgres store.
 */
export function memoryCveIndexStore(data: { state: CveIndexState | null; matches: CveMatchRow[]; records: CveRecordRow[] }): CveIndexStore {
  return {
    async readState() {
      return data.state;
    },
    async readMatches(vendor, product) {
      return data.matches.filter((r) => r.vendor === vendor && r.product === product);
    },
    async readRecords(cveIds) {
      const wanted = new Set(cveIds);
      return data.records.filter((r) => wanted.has(r.cve_id));
    },
  };
}

// Local CPE → CVE index: the build half. Pages through NVD's CVE API 2.0 and
// writes each CVE's version-bounded, vulnerable CPE criteria into Postgres
// (migration 069) for cveIndex.ts to read. Run nightly by
// .github/workflows/cve-index-sync.yml via src/scripts/sync-cve-index.ts.
//
// MODES
//   - Backfill: the first run pages through every CVE NVD holds (~300k, 2,000
//     per request). It records where it got to after each page, so a run that
//     times out resumes there. The index answers "error" to every lookup until
//     a backfill finishes — a half-built index would read as "no CVEs".
//   - Incremental: afterwards, each run asks for CVEs modified since the last
//     successful run (minus an hour of overlap), in windows of at most 120
//     days (NVD's limit on a lastMod date range). A rejected CVE is deleted.
//
// RATE LIMITS. NVD allows 5 requests per 30 seconds without a key and 50 with
// one (NVD_API_KEY, free from nvd.nist.gov). We sleep 6.5s or 0.7s between
// requests respectively, and back off on 403/429/503, which NVD returns when
// throttling. A backfill without a key takes about 20 minutes; with one, a few.
//
// What is stored is deliberately small: per CVE its best CVSS score and
// vector and a 300-character summary; per criterion only vulnerable,
// version-bounded ones (an exact version, or a start/end bound). A criterion
// naming every version is not evidence of anything and is dropped here.
import type { SupabaseClient } from "@supabase/supabase-js";
import { parseCpe, splitCpe23, type CveMatchRow, type CveRecordRow, type CveIndexState } from "./cveIndex";

export const NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
export const NVD_PAGE_SIZE = 2000;
/** NVD rejects a lastMod date range longer than this. */
export const NVD_MAX_RANGE_DAYS = 120;
const NVD_TIMEOUT_MS = 60_000;
const NVD_USER_AGENT = "HebridesCyberBot/1.0 (+https://www.hebridescyber.co.uk)";
const SUMMARY_MAX = 300;
const OVERLAP_MS = 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

// ---- NVD shapes (only what we read) ---------------------------------------------------

type NvdCvssMetric = { type?: string; cvssData?: { baseScore?: number; vectorString?: string; version?: string } };
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

export type NvdCve = {
  id?: string;
  vulnStatus?: string;
  published?: string;
  lastModified?: string;
  descriptions?: Array<{ lang?: string; value?: string }>;
  metrics?: {
    cvssMetricV31?: NvdCvssMetric[];
    cvssMetricV30?: NvdCvssMetric[];
    cvssMetricV40?: NvdCvssMetric[];
    cvssMetricV2?: NvdCvssMetric[];
  };
  configurations?: NvdConfiguration[];
};

export type NvdPage = { totalResults: number; startIndex: number; resultsPerPage: number; cves: NvdCve[] };

// ---- NVD record → index rows (pure) ----------------------------------------------------------

export type CveIndexEntry =
  | { cve_id: string; rejected: true }
  | { cve_id: string; rejected: false; record: CveRecordRow & { vuln_status: string | null }; matches: Omit<CveMatchRow, "cve_id">[] };

/** NVD writes timestamps without a zone; they are UTC. */
function nvdTimestamp(raw: string | undefined): string | null {
  if (!raw) return null;
  const iso = /[zZ]|[+-]\d\d:?\d\d$/.test(raw) ? raw : `${raw}Z`;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

/** NVD's primary score first, then any; CVSS 3.1, 3.0, 4.0, then 2.0. */
function bestCvss(metrics: NvdCve["metrics"]): { score: number; vector: string | null; version: string } | null {
  const lists: Array<[NvdCvssMetric[] | undefined, string]> = [
    [metrics?.cvssMetricV31, "3.1"],
    [metrics?.cvssMetricV30, "3.0"],
    [metrics?.cvssMetricV40, "4.0"],
    [metrics?.cvssMetricV2, "2.0"],
  ];
  for (const [list, version] of lists) {
    if (!list || list.length === 0) continue;
    const pick = list.find((m) => m.type === "Primary") ?? list[0];
    const score = pick.cvssData?.baseScore;
    if (typeof score === "number" && Number.isFinite(score)) return { score, vector: pick.cvssData?.vectorString ?? null, version };
  }
  return null;
}

/** The criteria a CVE's configurations mark vulnerable, version-bounded, deduplicated. */
export function criteriaFromConfigurations(configurations: NvdConfiguration[] | undefined): Omit<CveMatchRow, "cve_id">[] {
  const out = new Map<string, Omit<CveMatchRow, "cve_id">>();
  for (const config of configurations ?? []) {
    const nodes = config.nodes ?? [];
    if (config.negate) continue;
    const configConditional = config.operator === "AND" && nodes.length > 1;
    for (const node of nodes) {
      if (node.negate) continue; // describes what is NOT affected
      const matches = node.cpeMatch ?? [];
      const conditional = configConditional || (node.operator === "AND" && matches.length > 1);
      for (const m of matches) {
        if (m.vulnerable !== true || typeof m.criteria !== "string") continue;
        const name = parseCpe(m.criteria);
        if (!name) continue;
        const update = m.criteria.startsWith("cpe:2.3:") ? splitCpe23(m.criteria)[6] : undefined;
        const exact = name.version;
        const row: Omit<CveMatchRow, "cve_id"> = {
          part: name.part,
          vendor: name.vendor,
          product: name.product,
          exact_version: exact,
          any_update: exact !== null && update === "*",
          start_including: exact ? null : m.versionStartIncluding ?? null,
          start_excluding: exact ? null : m.versionStartExcluding ?? null,
          end_including: exact ? null : m.versionEndIncluding ?? null,
          end_excluding: exact ? null : m.versionEndExcluding ?? null,
          conditional,
          criteria: m.criteria,
        };
        if (!row.exact_version && !row.start_including && !row.start_excluding && !row.end_including && !row.end_excluding) continue;
        const key = [row.criteria, row.start_including, row.start_excluding, row.end_including, row.end_excluding].join("|");
        const seen = out.get(key);
        // The same criterion unconditionally elsewhere in the record wins.
        if (!seen || (seen.conditional && !row.conditional)) out.set(key, row);
      }
    }
  }
  return [...out.values()];
}

export function toIndexEntry(cve: NvdCve): CveIndexEntry | null {
  const id = cve.id?.toUpperCase();
  if (!id || !CVE_RE.test(id)) return null;
  if (cve.vulnStatus === "Rejected") return { cve_id: id, rejected: true };
  const lastModified = nvdTimestamp(cve.lastModified);
  if (!lastModified) return null;
  const cvss = bestCvss(cve.metrics);
  const summary = (cve.descriptions ?? []).find((d) => d.lang === "en")?.value?.trim() ?? null;
  return {
    cve_id: id,
    rejected: false,
    record: {
      cve_id: id,
      cvss_score: cvss?.score ?? null,
      cvss_version: cvss?.version ?? null,
      cvss_vector: cvss?.vector ?? null,
      summary: summary ? (summary.length > SUMMARY_MAX ? `${summary.slice(0, SUMMARY_MAX - 1)}…` : summary) : null,
      published_at: nvdTimestamp(cve.published),
      last_modified_at: lastModified,
      vuln_status: cve.vulnStatus ?? null,
    },
    matches: criteriaFromConfigurations(cve.configurations),
  };
}

// ---- NVD client ------------------------------------------------------------------------

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

/** NVD wants ISO-8601 with an explicit offset. */
export function nvdDate(d: Date): string {
  return d.toISOString().replace("Z", "+00:00");
}

export function nvdPageUrl(startIndex: number, window?: { start: Date; end: Date }): string {
  const params = new URLSearchParams({ startIndex: String(startIndex), resultsPerPage: String(NVD_PAGE_SIZE) });
  if (window) {
    params.set("lastModStartDate", nvdDate(window.start));
    params.set("lastModEndDate", nvdDate(window.end));
  }
  return `${NVD_CVE_API}?${params.toString()}`;
}

export function parseNvdPage(body: unknown): NvdPage | null {
  const b = body as { totalResults?: unknown; startIndex?: unknown; resultsPerPage?: unknown; vulnerabilities?: Array<{ cve?: NvdCve }> } | null;
  if (!b || typeof b.totalResults !== "number" || !Array.isArray(b.vulnerabilities)) return null;
  return {
    totalResults: b.totalResults,
    startIndex: typeof b.startIndex === "number" ? b.startIndex : 0,
    resultsPerPage: typeof b.resultsPerPage === "number" ? b.resultsPerPage : b.vulnerabilities.length,
    cves: b.vulnerabilities.map((v) => v.cve).filter((c): c is NvdCve => Boolean(c)),
  };
}

export type NvdClientOptions = {
  apiKey?: string;
  fetchImpl?: FetchLike;
  sleep?: (ms: number) => Promise<void>;
  /** Attempts per page before giving up. */
  attempts?: number;
};

const realSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** One page, retried with backoff when NVD throttles. Throws when it can't be read. */
export async function fetchNvdPage(url: string, options: NvdClientOptions = {}): Promise<NvdPage> {
  const fetchImpl = options.fetchImpl ?? (fetch as FetchLike);
  const sleep = options.sleep ?? realSleep;
  const attempts = options.attempts ?? 5;
  const headers: Record<string, string> = { "User-Agent": NVD_USER_AGENT };
  if (options.apiKey) headers.apiKey = options.apiKey;
  let lastError = "";
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const res = await fetchImpl(url, { headers, signal: AbortSignal.timeout(NVD_TIMEOUT_MS) });
      if (res.ok) {
        const page = parseNvdPage(await res.json());
        if (page) return page;
        lastError = "NVD response was not a CVE API 2.0 page";
      } else {
        lastError = `NVD answered HTTP ${res.status}`;
        if (![403, 429, 500, 502, 503, 504].includes(res.status)) break;
      }
    } catch (err) {
      lastError = `NVD request failed: ${(err as Error).message}`;
    }
    if (attempt < attempts) await sleep(Math.min(60_000, 6_000 * 2 ** (attempt - 1)));
  }
  throw new Error(lastError);
}

// ---- Sync -------------------------------------------------------------------------------

export type CveSyncState = CveIndexState & {
  backfill_started_at: string | null;
  backfill_next_index: number | null;
};

/** Where the sync writes. Each method throws on failure. */
export interface CveIndexWriter {
  readState(): Promise<CveSyncState | null>;
  writeEntries(entries: CveIndexEntry[]): Promise<void>;
  writeState(patch: Partial<CveSyncState> & { last_run_at: string; last_error: string | null }): Promise<void>;
  countRecords(): Promise<number>;
}

export type CveSyncSummary = {
  mode: "backfill" | "incremental";
  pages: number;
  cves: number;
  rejected: number;
  criteria: number;
  completed: boolean;
};

export type CveSyncOptions = NvdClientOptions & {
  now?: Date;
  /** Stop (resumably) after this many pages — keeps one run inside its time limit. */
  maxPages?: number;
  log?: (line: string) => void;
};

/** Dedupe within a page: the same CVE twice would violate the primary key. */
function dedupe(entries: CveIndexEntry[]): CveIndexEntry[] {
  const byId = new Map<string, CveIndexEntry>();
  for (const e of entries) byId.set(e.cve_id, e);
  return [...byId.values()];
}

/** Incremental windows from `since` to `now`, each at most NVD_MAX_RANGE_DAYS long. */
export function incrementalWindows(since: Date, now: Date): Array<{ start: Date; end: Date }> {
  const windows: Array<{ start: Date; end: Date }> = [];
  let start = new Date(since.getTime() - OVERLAP_MS);
  while (start < now) {
    const end = new Date(Math.min(now.getTime(), start.getTime() + NVD_MAX_RANGE_DAYS * DAY_MS));
    windows.push({ start, end });
    start = end;
  }
  return windows;
}

/**
 * Brings the index up to date. Throws on any failed NVD read or write, after
 * recording the error in cve_index_state; a failed run never moves
 * last_modified_through forward, so the next run re-reads the same window.
 */
export async function syncCveIndex(writer: CveIndexWriter, options: CveSyncOptions = {}): Promise<CveSyncSummary> {
  const now = options.now ?? new Date();
  const sleep = options.sleep ?? realSleep;
  const pause = options.apiKey ? 700 : 6_500;
  const log = options.log ?? (() => {});
  const maxPages = options.maxPages ?? Number.POSITIVE_INFINITY;
  const runAt = now.toISOString();

  const state = await writer.readState();
  const backfilling = !state?.backfill_completed_at;
  const summary: CveSyncSummary = { mode: backfilling ? "backfill" : "incremental", pages: 0, cves: 0, rejected: 0, criteria: 0, completed: false };

  const writePage = async (page: NvdPage) => {
    const entries = dedupe(page.cves.map(toIndexEntry).filter((e): e is CveIndexEntry => e !== null));
    if (entries.length > 0) await writer.writeEntries(entries);
    summary.pages++;
    summary.cves += entries.length;
    for (const e of entries) {
      if (e.rejected) summary.rejected++;
      else summary.criteria += e.matches.length;
    }
  };

  try {
    if (backfilling) {
      const startedAt = state?.backfill_started_at ?? runAt;
      let index = state?.backfill_next_index ?? 0;
      if (!state?.backfill_started_at) await writer.writeState({ backfill_started_at: startedAt, backfill_next_index: 0, last_run_at: runAt, last_error: null });
      for (;;) {
        if (summary.pages >= maxPages) {
          log(`Backfill paused at index ${index}; the next run resumes there.`);
          await writer.writeState({ backfill_next_index: index, last_run_at: runAt, last_error: null });
          return summary;
        }
        if (summary.pages > 0) await sleep(pause);
        const page = await fetchNvdPage(nvdPageUrl(index), options);
        await writePage(page);
        index = page.startIndex + page.cves.length;
        log(`Backfill: ${index}/${page.totalResults}`);
        await writer.writeState({ backfill_next_index: index, last_run_at: runAt, last_error: null });
        if (page.cves.length === 0 || index >= page.totalResults) break;
      }
      // Changes made while the backfill ran are picked up by the next incremental run.
      await writer.writeState({
        backfill_completed_at: runAt,
        backfill_next_index: null,
        last_modified_through: startedAt,
        last_success_at: runAt,
        cve_count: await writer.countRecords(),
        last_run_at: runAt,
        last_error: null,
      });
      summary.completed = true;
      return summary;
    }

    const since = new Date(state?.last_modified_through ?? state?.backfill_started_at ?? runAt);
    for (const window of incrementalWindows(since, now)) {
      let index = 0;
      for (;;) {
        if (summary.pages > 0) await sleep(pause);
        const page = await fetchNvdPage(nvdPageUrl(index, window), options);
        await writePage(page);
        index = page.startIndex + page.cves.length;
        if (page.cves.length === 0 || index >= page.totalResults) break;
      }
    }
    await writer.writeState({
      last_modified_through: runAt,
      last_success_at: runAt,
      cve_count: await writer.countRecords(),
      last_run_at: runAt,
      last_error: null,
    });
    summary.completed = true;
    return summary;
  } catch (err) {
    const message = (err as Error).message;
    try {
      await writer.writeState({ last_run_at: runAt, last_error: message.slice(0, 500) });
    } catch {
      // The original error is the one worth reporting.
    }
    throw err;
  }
}

// ---- Postgres writer ----------------------------------------------------------------------

const STATE_COLUMNS =
  "backfill_started_at, backfill_next_index, backfill_completed_at, last_success_at, last_modified_through, cve_count";

/** Writes through the service role; the batch RPC replaces each CVE's rows atomically. */
export function supabaseCveIndexWriter(client: SupabaseClient): CveIndexWriter {
  return {
    async readState() {
      const { data, error } = await client.from("cve_index_state").select(STATE_COLUMNS).eq("id", true).maybeSingle();
      if (error) throw new Error(`cve_index_state read failed: ${error.message}`);
      return (data as CveSyncState | null) ?? null;
    },
    async writeEntries(entries) {
      const payload = entries.map((e) => (e.rejected ? e : { cve_id: e.cve_id, rejected: false, ...e.record, matches: e.matches }));
      const { error } = await client.rpc("replace_cve_batch", { p_entries: payload });
      if (error) throw new Error(`replace_cve_batch failed: ${error.message}`);
    },
    async writeState(patch) {
      const { error } = await client.from("cve_index_state").upsert({ id: true, ...patch }, { onConflict: "id" });
      if (error) throw new Error(`cve_index_state write failed: ${error.message}`);
    },
    async countRecords() {
      const { count, error } = await client.from("cve_records").select("cve_id", { count: "exact", head: true });
      if (error) throw new Error(`cve_records count failed: ${error.message}`);
      return count ?? 0;
    },
  };
}

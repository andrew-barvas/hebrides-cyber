// The CPE → CVE index in object storage instead of Postgres. At 2.2 million
// criteria and 400,000 CVEs it took 612 MB, over the Supabase Free plan's
// whole 500 MB database limit; as gzipped objects it is a fraction of that
// and counts against file storage, not the database.
//
// LAYOUT (prefix v1/):
//   state.json                 the sync state (CveSyncState)
//   matches/<n>.json.gz        n = hash(vendor:product) % MATCH_BUCKETS;
//                              { "vendor:product": [criterion, …] }
//   records/<n>.json.gz        n = hash(cve_id) % RECORD_BUCKETS;
//                              { CVE-…: { r: record, p: ["vendor:product", …] } }
// A record lists the products it has criteria for, so an update or a
// rejection removes the CVE's old criteria everywhere, as the Postgres
// replace_cve_batch did.
//
// Reads touch one matches object per product looked up and one records
// object per bucket of matched CVEs, cached for the life of the store.
import { gunzipSync, gzipSync } from "node:zlib";
import type { CveIndexStore, CveIndexState, CveMatchRow, CveRecordRow } from "./cveIndex";
import type { CveIndexEntry, CveIndexWriter, CveSyncState } from "./cveIndexFeed";
import type { ObjectStore } from "./objectStore";

export const MATCH_BUCKETS = 1024;
export const RECORD_BUCKETS = 256;
const PREFIX = "v1";
const STATE_KEY = `${PREFIX}/state.json`;
const UPLOAD_CONCURRENCY = 16;

type StoredMatch = Omit<CveMatchRow, "vendor" | "product">;
type MatchBucket = Record<string, StoredMatch[]>;
type StoredRecord = { r: Omit<CveRecordRow, "cve_id"> & { vuln_status?: string | null }; p: string[] };
type RecordBucket = Record<string, StoredRecord>;

/** FNV-1a, 32-bit: stable across runs and platforms. */
export function bucketOf(key: string, buckets: number): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) {
    h ^= key.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h % buckets;
}

export const productKey = (vendor: string, product: string) => `${vendor}:${product}`;
const matchKey = (n: number) => `${PREFIX}/matches/${n}.json.gz`;
const recordKey = (n: number) => `${PREFIX}/records/${n}.json.gz`;

export function encodeJson(value: unknown): Buffer {
  return gzipSync(Buffer.from(JSON.stringify(value)), { level: 9 });
}
export function decodeJson<T>(data: Buffer): T {
  return JSON.parse(gunzipSync(data).toString("utf8")) as T;
}

async function readState(store: ObjectStore): Promise<CveSyncState | null> {
  const raw = await store.get(STATE_KEY);
  return raw ? (JSON.parse(raw.toString("utf8")) as CveSyncState) : null;
}

/** Runs `fn` over items with bounded concurrency; the first failure rejects. */
async function inParallel<T>(items: T[], fn: (item: T) => Promise<void>, limit = UPLOAD_CONCURRENCY): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) await fn(items[next++]);
  });
  await Promise.all(workers);
}

// ---- Read side ----------------------------------------------------------------------------

export function objectCveIndexStore(store: ObjectStore): CveIndexStore {
  const matchCache = new Map<number, Promise<MatchBucket>>();
  const recordCache = new Map<number, Promise<RecordBucket>>();
  const load = <T>(cache: Map<number, Promise<T>>, n: number, key: string) => {
    let p = cache.get(n);
    if (!p) {
      p = store.get(key).then((raw) => (raw ? decodeJson<T>(raw) : ({} as T)));
      p.catch(() => cache.delete(n));
      cache.set(n, p);
    }
    return p;
  };
  return {
    async readState(): Promise<CveIndexState | null> {
      const s = await readState(store);
      return s ? { backfill_completed_at: s.backfill_completed_at, last_success_at: s.last_success_at, last_modified_through: s.last_modified_through, cve_count: s.cve_count } : null;
    },
    async readMatches(vendor, product) {
      const key = productKey(vendor, product);
      const n = bucketOf(key, MATCH_BUCKETS);
      const bucket = await load(matchCache, n, matchKey(n));
      return (bucket[key] ?? []).map((m) => ({ ...m, vendor, product }));
    },
    async readRecords(cveIds) {
      const byBucket = new Map<number, string[]>();
      for (const id of cveIds) {
        const n = bucketOf(id, RECORD_BUCKETS);
        byBucket.set(n, [...(byBucket.get(n) ?? []), id]);
      }
      const out: CveRecordRow[] = [];
      for (const [n, ids] of byBucket) {
        const bucket = await load(recordCache, n, recordKey(n));
        for (const id of ids) {
          const rec = bucket[id];
          if (rec) {
            const { vuln_status: _status, ...r } = rec.r;
            void _status;
            out.push({ cve_id: id, ...r });
          }
        }
      }
      return out;
    },
  };
}

// ---- Write side ---------------------------------------------------------------------------

export type ObjectCveIndexWriter = CveIndexWriter & {
  /** Uploads every changed object, then the state. */
  flush(): Promise<void>;
};

/**
 * Buffers changes in memory. Once the backfill has completed, every
 * writeState flushes (an incremental run writes state once, at the end).
 * During a backfill only completion or an explicit flush() (a pause) writes,
 * so a whole rebuild uploads each object once rather than once per page.
 */
export function objectCveIndexWriter(store: ObjectStore): ObjectCveIndexWriter {
  const matchBuckets = new Map<number, MatchBucket>();
  const recordBuckets = new Map<number, RecordBucket>();
  const dirtyMatches = new Set<number>();
  const dirtyRecords = new Set<number>();
  let state: CveSyncState | null | undefined;
  let countDelta = 0;

  const loadMatches = async (n: number) => {
    let b = matchBuckets.get(n);
    if (!b) {
      const raw = await store.get(matchKey(n));
      b = raw ? decodeJson<MatchBucket>(raw) : {};
      matchBuckets.set(n, b);
    }
    return b;
  };
  const loadRecords = async (n: number) => {
    let b = recordBuckets.get(n);
    if (!b) {
      const raw = await store.get(recordKey(n));
      b = raw ? decodeJson<RecordBucket>(raw) : {};
      recordBuckets.set(n, b);
    }
    return b;
  };
  const currentState = async () => {
    if (state === undefined) state = await readState(store);
    return state;
  };

  const writer: ObjectCveIndexWriter = {
    async readState() {
      return currentState();
    },
    async writeEntries(entries: CveIndexEntry[]) {
      for (const entry of entries) {
        const rn = bucketOf(entry.cve_id, RECORD_BUCKETS);
        const records = await loadRecords(rn);
        const previous = records[entry.cve_id];
        const newProducts = entry.rejected ? [] : [...new Set(entry.matches.map((m) => productKey(m.vendor, m.product)))];
        for (const key of new Set([...(previous?.p ?? []), ...newProducts])) {
          const mn = bucketOf(key, MATCH_BUCKETS);
          const bucket = await loadMatches(mn);
          const kept = (bucket[key] ?? []).filter((m) => m.cve_id !== entry.cve_id);
          if (!entry.rejected) {
            for (const m of entry.matches) {
              if (productKey(m.vendor, m.product) !== key) continue;
              const { vendor: _v, product: _p, ...rest } = m;
              void _v;
              void _p;
              kept.push({ cve_id: entry.cve_id, ...rest });
            }
          }
          if (kept.length > 0) bucket[key] = kept;
          else delete bucket[key];
          dirtyMatches.add(mn);
        }
        if (entry.rejected) {
          if (previous) {
            delete records[entry.cve_id];
            countDelta--;
          }
        } else {
          const { cve_id: _id, ...r } = entry.record;
          void _id;
          if (!previous) countDelta++;
          records[entry.cve_id] = { r, p: newProducts };
        }
        dirtyRecords.add(rn);
      }
    },
    async writeState(patch) {
      const base = (await currentState()) ?? ({} as CveSyncState);
      state = { ...base, ...patch } as CveSyncState;
      const backfilling = !state.backfill_completed_at;
      if (!backfilling || patch.backfill_completed_at) await writer.flush();
    },
    async countRecords() {
      const base = (await currentState())?.cve_count ?? 0;
      return Math.max(0, base + countDelta);
    },
    async flush() {
      const matchJobs = [...dirtyMatches].map((n) => async () => store.put(matchKey(n), encodeJson(matchBuckets.get(n) ?? {}), "application/gzip"));
      const recordJobs = [...dirtyRecords].map((n) => async () => store.put(recordKey(n), encodeJson(recordBuckets.get(n) ?? {}), "application/gzip"));
      await inParallel([...matchJobs, ...recordJobs], (job) => job());
      dirtyMatches.clear();
      dirtyRecords.clear();
      // State last: a crash part-way leaves the old state pointing at data that is at least as new.
      const s = await currentState();
      if (s) await store.put(STATE_KEY, Buffer.from(JSON.stringify(s)), "application/json");
    },
  };
  return writer;
}

/**
 * Builds every object from complete row sets in one pass (the one-off move
 * from Postgres): no reads, each object written once.
 */
export async function writeFullIndex(
  store: ObjectStore,
  data: { records: Array<CveRecordRow & { vuln_status?: string | null }>; matches: CveMatchRow[]; state: CveSyncState }
): Promise<{ matchObjects: number; recordObjects: number; bytes: number }> {
  const matchBuckets = new Map<number, MatchBucket>();
  const productsByCve = new Map<string, Set<string>>();
  for (const m of data.matches) {
    const key = productKey(m.vendor, m.product);
    const n = bucketOf(key, MATCH_BUCKETS);
    const bucket = matchBuckets.get(n) ?? {};
    const { vendor: _v, product: _p, ...rest } = m;
    void _v;
    void _p;
    (bucket[key] ??= []).push(rest);
    matchBuckets.set(n, bucket);
    const set = productsByCve.get(m.cve_id) ?? new Set<string>();
    set.add(key);
    productsByCve.set(m.cve_id, set);
  }
  const recordBuckets = new Map<number, RecordBucket>();
  for (const rec of data.records) {
    const n = bucketOf(rec.cve_id, RECORD_BUCKETS);
    const bucket = recordBuckets.get(n) ?? {};
    const { cve_id, ...r } = rec;
    bucket[cve_id] = { r, p: [...(productsByCve.get(cve_id) ?? [])] };
    recordBuckets.set(n, bucket);
  }
  let bytes = 0;
  const jobs: Array<() => Promise<void>> = [];
  for (let n = 0; n < MATCH_BUCKETS; n++) {
    const body = encodeJson(matchBuckets.get(n) ?? {});
    bytes += body.length;
    jobs.push(() => store.put(matchKey(n), body, "application/gzip"));
  }
  for (let n = 0; n < RECORD_BUCKETS; n++) {
    const body = encodeJson(recordBuckets.get(n) ?? {});
    bytes += body.length;
    jobs.push(() => store.put(recordKey(n), body, "application/gzip"));
  }
  await inParallel(jobs, (job) => job());
  await store.put(STATE_KEY, Buffer.from(JSON.stringify({ ...data.state, cve_count: data.records.length })), "application/json");
  return { matchObjects: MATCH_BUCKETS, recordObjects: RECORD_BUCKETS, bytes };
}

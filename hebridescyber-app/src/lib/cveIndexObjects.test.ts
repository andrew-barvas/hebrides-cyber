import { describe, expect, it } from "vitest";
import { bucketOf, decodeJson, encodeJson, MATCH_BUCKETS, objectCveIndexStore, objectCveIndexWriter, RECORD_BUCKETS, writeFullIndex } from "./cveIndexObjects";
import { createCveIndex, type CveMatchRow, type CveRecordRow } from "./cveIndex";
import { syncCveIndex, type CveIndexEntry, type CveSyncState } from "./cveIndexFeed";
import { memoryObjectStore } from "./objectStore";

const record = (id: string, over: Partial<CveRecordRow> = {}): CveRecordRow & { vuln_status: string | null } => ({
  cve_id: id, cvss_score: 7.5, cvss_version: "3.1", cvss_vector: "CVSS:3.1/AV:N", summary: `Issue ${id}`, published_at: "2024-01-01T00:00:00.000Z", last_modified_at: "2024-02-01T00:00:00.000Z", vuln_status: "Analyzed", ...over,
});
const match = (id: string, vendor: string, product: string, endExcluding = "2.4.58"): CveMatchRow => ({
  cve_id: id, part: "a", vendor, product, exact_version: null, any_update: false, start_including: null, start_excluding: null, end_including: null, end_excluding: endExcluding, conditional: false, criteria: `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`,
});
const entry = (id: string, products: Array<[string, string]>): CveIndexEntry => ({
  cve_id: id, rejected: false, record: record(id), matches: products.map(([v, p]) => { const { cve_id: _c, ...m } = match(id, v, p); void _c; return m; }),
});
const completeState: CveSyncState = { backfill_started_at: "2026-11-01T00:00:00.000Z", backfill_next_index: null, backfill_completed_at: "2026-11-10T00:00:00.000Z", last_success_at: "2026-11-19T00:00:00.000Z", last_modified_through: "2026-11-19T00:00:00.000Z", cve_count: 0 };

describe("bucketOf and encoding", () => {
  it("is stable and in range", () => {
    expect(bucketOf("apache:http_server", MATCH_BUCKETS)).toBe(bucketOf("apache:http_server", MATCH_BUCKETS));
    for (const k of ["a", "nginx:nginx", "CVE-2024-1234"]) expect(bucketOf(k, RECORD_BUCKETS)).toBeLessThan(RECORD_BUCKETS);
  });
  it("round-trips gzip JSON", () => {
    expect(decodeJson(encodeJson({ a: [1, 2] }))).toEqual({ a: [1, 2] });
  });
});

describe("writeFullIndex + objectCveIndexStore", () => {
  it("answers lookups exactly like the rows it was built from", async () => {
    const store = memoryObjectStore();
    await writeFullIndex(store, {
      records: [record("CVE-2024-0001"), record("CVE-2024-0002")],
      matches: [match("CVE-2024-0001", "apache", "http_server"), match("CVE-2024-0002", "apache", "http_server", "2.4.50"), match("CVE-2024-0002", "nginx", "nginx", "1.25.0")],
      state: completeState,
    });
    expect(store.keys()).toHaveLength(MATCH_BUCKETS + RECORD_BUCKETS + 1);
    const read = objectCveIndexStore(store);
    expect((await read.readState())?.cve_count).toBe(2);
    expect((await read.readMatches("apache", "http_server")).map((m) => m.cve_id).sort()).toEqual(["CVE-2024-0001", "CVE-2024-0002"]);
    expect(await read.readMatches("nobody", "nothing")).toEqual([]);
    const recs = await read.readRecords(["CVE-2024-0002", "CVE-2024-9999"]);
    expect(recs).toEqual([expect.objectContaining({ cve_id: "CVE-2024-0002", cvss_score: 7.5, summary: "Issue CVE-2024-0002" })]);
    expect(recs[0]).not.toHaveProperty("vuln_status");

    const index = createCveIndex(read, { now: new Date("2026-11-20T00:00:00Z") });
    const result = await index.lookup({ vendor: "apache", product: "http_server", version: "2.4.49" } as never);
    expect(JSON.stringify(result)).toContain("CVE-2024-0001");
  });
});

describe("objectCveIndexWriter", () => {
  it("replaces a CVE's criteria everywhere on update, removes it on rejection, and keeps the count", async () => {
    const store = memoryObjectStore();
    await writeFullIndex(store, { records: [record("CVE-2024-0001")], matches: [match("CVE-2024-0001", "apache", "http_server"), match("CVE-2024-0001", "old", "product")], state: completeState });

    const w = objectCveIndexWriter(store);
    await w.writeEntries([entry("CVE-2024-0001", [["apache", "http_server"]]), entry("CVE-2024-0003", [["nginx", "nginx"]])]);
    await w.writeEntries([{ cve_id: "CVE-2024-0003", rejected: true }, entry("CVE-2024-0004", [["nginx", "nginx"]])]);
    expect(await w.countRecords()).toBe(2);
    await w.writeState({ last_success_at: "2026-11-20T00:00:00.000Z", cve_count: await w.countRecords(), last_run_at: "2026-11-20T00:00:00.000Z", last_error: null });

    const read = objectCveIndexStore(store);
    expect(await read.readMatches("old", "product")).toEqual([]);
    expect((await read.readMatches("apache", "http_server")).map((m) => m.cve_id)).toEqual(["CVE-2024-0001"]);
    expect((await read.readMatches("nginx", "nginx")).map((m) => m.cve_id)).toEqual(["CVE-2024-0004"]);
    expect(await read.readRecords(["CVE-2024-0003"])).toEqual([]);
    expect((await read.readState())?.cve_count).toBe(2);
  });

  it("during a backfill writes nothing until completion or an explicit flush", async () => {
    const store = memoryObjectStore();
    const w = objectCveIndexWriter(store);
    await w.writeEntries([entry("CVE-2024-0001", [["apache", "http_server"]])]);
    await w.writeState({ backfill_started_at: "2026-11-20T00:00:00.000Z", backfill_next_index: 2000, last_run_at: "x", last_error: null });
    expect(store.puts).toBe(0);
    await w.flush();
    expect(store.puts).toBeGreaterThan(0);
    expect((await objectCveIndexStore(store).readMatches("apache", "http_server"))).toHaveLength(1);
  });

  it("is what syncCveIndex flushes when a backfill pauses", async () => {
    const store = memoryObjectStore();
    const page = { totalResults: 4000, startIndex: 0, resultsPerPage: 2000, vulnerabilities: [{ cve: { id: "CVE-2024-0007", vulnStatus: "Analyzed", lastModified: "2024-02-01T00:00:00.000", descriptions: [{ lang: "en", value: "x" }], configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", versionEndExcluding: "2.4.58" }] }] }] } }] };
    const fetchImpl = async () => new Response(JSON.stringify(page), { status: 200 });
    const summary = await syncCveIndex(objectCveIndexWriter(store), { maxPages: 1, fetchImpl, sleep: async () => {}, now: new Date("2026-11-20T00:00:00Z") } as never);
    expect(summary.completed).toBe(false);
    const read = objectCveIndexStore(store);
    expect((await read.readState())?.backfill_completed_at ?? null).toBeNull();
    expect((await read.readMatches("apache", "http_server")).map((m) => m.cve_id)).toEqual(["CVE-2024-0007"]);
  });
});

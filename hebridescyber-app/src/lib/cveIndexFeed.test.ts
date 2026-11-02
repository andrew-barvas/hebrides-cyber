import { describe, it, expect, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  toIndexEntry,
  criteriaFromConfigurations,
  parseNvdPage,
  fetchNvdPage,
  nvdPageUrl,
  nvdDate,
  incrementalWindows,
  syncCveIndex,
  supabaseCveIndexWriter,
  NVD_MAX_RANGE_DAYS,
  type NvdCve,
  type CveIndexWriter,
  type CveSyncState,
  type CveIndexEntry,
  type FetchLike,
} from "./cveIndexFeed";

// Trimmed from NVD's CVE API 2.0 record for CVE-2024-6387: its OpenSSH
// criteria, one AND configuration pairing a vulnerable firmware with a
// non-vulnerable appliance, and both CVSS 3.1 entries (Secondary first).
const REGRESSHION: NvdCve = {
  id: "CVE-2024-6387",
  vulnStatus: "Modified",
  published: "2024-07-01T13:15:01.677",
  lastModified: "2025-09-30T14:19:23.457",
  descriptions: [
    { lang: "en", value: "A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). " + "x".repeat(400) },
    { lang: "es", value: "Una regresión" },
  ],
  metrics: {
    cvssMetricV31: [
      { type: "Secondary", cvssData: { baseScore: 8.1, vectorString: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" } },
      { type: "Primary", cvssData: { baseScore: 8.1, vectorString: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" } },
    ],
  },
  configurations: [
    {
      nodes: [
        {
          operator: "OR",
          negate: false,
          cpeMatch: [
            { vulnerable: true, criteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", versionEndExcluding: "4.4" },
            { vulnerable: true, criteria: "cpe:2.3:a:openbsd:openssh:4.4:-:*:*:*:*:*:*" },
            { vulnerable: true, criteria: "cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*" },
            { vulnerable: true, criteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", versionStartIncluding: "8.6", versionEndIncluding: "9.8" },
            // Every version, no bound: not evidence, never stored.
            { vulnerable: true, criteria: "cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*" },
            { vulnerable: true, criteria: "cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*" },
          ],
        },
      ],
    },
    {
      operator: "AND",
      nodes: [
        { operator: "OR", cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:o:sonicwall:sma_100_firmware:*:*:*:*:*:*:*:*", versionEndExcluding: "10.2.1.13" }] },
        { operator: "OR", cpeMatch: [{ vulnerable: false, criteria: "cpe:2.3:h:sonicwall:sma_200:-:*:*:*:*:*:*:*" }] },
      ],
    },
  ],
};

describe("toIndexEntry", () => {
  it("keeps the best score, a short summary and only version-bounded vulnerable criteria", () => {
    const entry = toIndexEntry(REGRESSHION);
    expect(entry?.rejected).toBe(false);
    if (!entry || entry.rejected) return;
    expect(entry.record).toMatchObject({
      cve_id: "CVE-2024-6387",
      cvss_score: 8.1,
      cvss_version: "3.1",
      cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
      published_at: "2024-07-01T13:15:01.677Z",
      last_modified_at: "2025-09-30T14:19:23.457Z",
      vuln_status: "Modified",
    });
    expect(entry.record.summary!.length).toBe(300);
    expect(entry.record.summary!.endsWith("…")).toBe(true);
    expect(entry.matches.map((m) => [m.vendor, m.product, m.exact_version, m.any_update, m.start_including, m.end_including, m.end_excluding, m.conditional])).toEqual([
      ["openbsd", "openssh", null, false, null, null, "4.4", false],
      ["openbsd", "openssh", "4.4", false, null, null, null, false],
      ["openbsd", "openssh", "8.5p1", false, null, null, null, false],
      ["openbsd", "openssh", null, false, "8.6", "9.8", null, false],
      ["redhat", "enterprise_linux", "8.0", true, null, null, null, false],
      ["sonicwall", "sma_100_firmware", null, false, null, null, "10.2.1.13", true],
    ]);
  });

  it("marks a rejected CVE for deletion and skips records it can't key", () => {
    expect(toIndexEntry({ id: "CVE-2023-9999", vulnStatus: "Rejected" })).toEqual({ cve_id: "CVE-2023-9999", rejected: true });
    expect(toIndexEntry({ id: "not-a-cve", lastModified: "2025-01-01T00:00:00.000" })).toBeNull();
    expect(toIndexEntry({ id: "CVE-2023-0001" })).toBeNull();
    expect(toIndexEntry({ id: "CVE-2023-0001", lastModified: "garbage" })).toBeNull();
  });

  it("falls back through CVSS versions and copes with no score or summary", () => {
    const v2 = toIndexEntry({ id: "CVE-2010-0001", lastModified: "2020-01-01T00:00:00.000Z", metrics: { cvssMetricV2: [{ cvssData: { baseScore: 7.5 } }] } });
    expect(v2 && !v2.rejected && v2.record).toMatchObject({ cvss_score: 7.5, cvss_version: "2.0", cvss_vector: null, summary: null, published_at: null });
    const v40 = toIndexEntry({ id: "CVE-2025-0001", lastModified: "2025-01-01T00:00:00.000", metrics: { cvssMetricV30: [{ cvssData: {} }], cvssMetricV40: [{ cvssData: { baseScore: 9.3 } }] } });
    expect(v40 && !v40.rejected && v40.record.cvss_version).toBe("4.0");
    const none = toIndexEntry({ id: "CVE-2025-0002", lastModified: "2025-01-01T00:00:00.000+00:00", descriptions: [{ lang: "en", value: "Short." }] });
    expect(none && !none.rejected && none.record).toMatchObject({ cvss_score: null, summary: "Short." });
  });
});

describe("criteriaFromConfigurations", () => {
  it("skips negated nodes and configurations, unparseable criteria and duplicates", () => {
    const rows = criteriaFromConfigurations([
      { negate: true, nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*" }] }] },
      {
        nodes: [
          { negate: true, cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:x:y:2.0:*:*:*:*:*:*:*" }] },
          {
            operator: "AND",
            cpeMatch: [
              { vulnerable: true, criteria: "cpe:2.3:a:x:y:3.0:-:*:*:*:*:*:*" },
              { vulnerable: true, criteria: "garbage" },
              { criteria: "cpe:2.3:a:x:z:1.0:*:*:*:*:*:*:*" },
            ],
          },
          { cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:x:y:3.0:-:*:*:*:*:*:*" }] },
        ],
      },
    ]);
    // The AND node's 3.0 is conditional; the same criterion unconditionally wins.
    expect(rows).toEqual([expect.objectContaining({ exact_version: "3.0", any_update: false, conditional: false })]);
    expect(criteriaFromConfigurations(undefined)).toEqual([]);
  });
});

describe("NVD client", () => {
  it("builds page URLs with lastMod windows in NVD's offset form", () => {
    expect(nvdDate(new Date("2026-11-01T00:00:00Z"))).toBe("2026-11-01T00:00:00.000+00:00");
    expect(nvdPageUrl(2000)).toBe("https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=2000&resultsPerPage=2000");
    const url = new URL(nvdPageUrl(0, { start: new Date("2026-10-01T00:00:00Z"), end: new Date("2026-11-01T00:00:00Z") }));
    expect(url.searchParams.get("lastModStartDate")).toBe("2026-10-01T00:00:00.000+00:00");
    expect(url.searchParams.get("lastModEndDate")).toBe("2026-11-01T00:00:00.000+00:00");
  });

  it("parses a CVE API page and rejects anything else", () => {
    expect(parseNvdPage({ totalResults: 1, startIndex: 0, resultsPerPage: 1, vulnerabilities: [{ cve: REGRESSHION }, {}] })).toEqual({
      totalResults: 1,
      startIndex: 0,
      resultsPerPage: 1,
      cves: [REGRESSHION],
    });
    expect(parseNvdPage({ totalResults: 0, vulnerabilities: [] })).toEqual({ totalResults: 0, startIndex: 0, resultsPerPage: 0, cves: [] });
    expect(parseNvdPage({ message: "oops" })).toBeNull();
    expect(parseNvdPage(null)).toBeNull();
  });

  it("sends the API key and retries when NVD throttles", async () => {
    const sleep = vi.fn(async () => {});
    const fetchImpl = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(new Response("", { status: 403 }))
      .mockRejectedValueOnce(new Error("socket hang up"))
      .mockResolvedValueOnce(new Response(JSON.stringify({ unexpected: true }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ totalResults: 0, vulnerabilities: [] }), { status: 200 }));
    const page = await fetchNvdPage("https://nvd.test/page", { apiKey: "k", fetchImpl, sleep });
    expect(page.totalResults).toBe(0);
    expect(fetchImpl).toHaveBeenCalledTimes(4);
    const headers = fetchImpl.mock.calls[0][1]?.headers as Record<string, string>;
    expect(headers.apiKey).toBe("k");
    expect(sleep.mock.calls.map((c) => (c as unknown[])[0])).toEqual([6000, 12000, 24000]);
  });

  it("gives up at once on a non-retryable status, and after its attempts otherwise", async () => {
    const notFound = vi.fn<FetchLike>().mockResolvedValue(new Response("", { status: 404 }));
    await expect(fetchNvdPage("https://nvd.test", { fetchImpl: notFound, sleep: async () => {} })).rejects.toThrow("NVD answered HTTP 404");
    expect(notFound).toHaveBeenCalledTimes(1);
    const busy = vi.fn<FetchLike>().mockResolvedValue(new Response("", { status: 503 }));
    await expect(fetchNvdPage("https://nvd.test", { fetchImpl: busy, sleep: async () => {}, attempts: 2 })).rejects.toThrow("HTTP 503");
    expect(busy).toHaveBeenCalledTimes(2);
  });

  it("splits a long gap into windows NVD accepts, with an hour's overlap", () => {
    const now = new Date("2026-11-01T00:00:00Z");
    const windows = incrementalWindows(new Date("2026-04-01T00:00:00Z"), now);
    expect(windows).toHaveLength(2);
    expect(windows[0].start.toISOString()).toBe("2026-03-31T23:00:00.000Z");
    expect(windows[0].end.getTime() - windows[0].start.getTime()).toBe(NVD_MAX_RANGE_DAYS * 86_400_000);
    expect(windows[1].end).toEqual(now);
  });
});

// ---- syncCveIndex ----------------------------------------------------------------------

function memoryWriter(initial: CveSyncState | null) {
  let state: CveSyncState | null = initial;
  const written: CveIndexEntry[][] = [];
  const patches: Array<Record<string, unknown>> = [];
  const writer: CveIndexWriter = {
    async readState() {
      return state;
    },
    async writeEntries(entries) {
      written.push(entries);
    },
    async writeState(patch) {
      patches.push(patch);
      state = { ...(state ?? { backfill_started_at: null, backfill_next_index: null, backfill_completed_at: null, last_success_at: null, last_modified_through: null, cve_count: null }), ...patch } as CveSyncState;
    },
    async countRecords() {
      return 42;
    },
  };
  return { writer, written, patches, getState: () => state };
}

function pageResponse(startIndex: number, total: number, cves: NvdCve[]): Response {
  return new Response(JSON.stringify({ totalResults: total, startIndex, resultsPerPage: cves.length, vulnerabilities: cves.map((cve) => ({ cve })) }), { status: 200 });
}

const cve = (n: number): NvdCve => ({ ...REGRESSHION, id: `CVE-2024-${String(n).padStart(5, "0")}` });
const NOW = new Date("2026-11-01T02:50:00Z");

describe("syncCveIndex", () => {
  it("backfills every page, then records completion and where incremental runs start", async () => {
    const { writer, written, getState } = memoryWriter(null);
    const fetchImpl = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(pageResponse(0, 4, [cve(1), cve(2), cve(2)]))
      .mockResolvedValueOnce(pageResponse(3, 4, [{ id: "CVE-2024-00003", vulnStatus: "Rejected" }]));
    const sleep = vi.fn(async () => {});
    const summary = await syncCveIndex(writer, { now: NOW, fetchImpl, sleep });
    expect(summary).toEqual({ mode: "backfill", pages: 2, cves: 3, rejected: 1, criteria: 12, completed: true });
    expect(written[0].map((e) => e.cve_id)).toEqual(["CVE-2024-00001", "CVE-2024-00002"]); // deduplicated
    expect(sleep).toHaveBeenCalledWith(6500); // no key: NVD's anonymous pace
    expect(getState()).toMatchObject({
      backfill_completed_at: NOW.toISOString(),
      backfill_next_index: null,
      last_modified_through: NOW.toISOString(),
      last_success_at: NOW.toISOString(),
      cve_count: 42,
      last_error: null,
    });
  });

  it("pauses a backfill at maxPages and resumes from that index next run", async () => {
    const first = memoryWriter(null);
    const fetchImpl = vi.fn<FetchLike>().mockResolvedValueOnce(pageResponse(0, 4, [cve(1), cve(2)]));
    const paused = await syncCveIndex(first.writer, { now: NOW, fetchImpl, sleep: async () => {}, maxPages: 1 });
    expect(paused.completed).toBe(false);
    expect(first.getState()).toMatchObject({ backfill_next_index: 2, backfill_completed_at: null, backfill_started_at: NOW.toISOString() });

    const later = new Date("2026-11-02T02:50:00Z");
    const resume = vi.fn<FetchLike>().mockResolvedValueOnce(pageResponse(2, 4, [cve(3), cve(4)]));
    const second = memoryWriter(first.getState());
    const done = await syncCveIndex(second.writer, { now: later, fetchImpl: resume, sleep: async () => {}, apiKey: "k" });
    expect(done.completed).toBe(true);
    expect(new URL(resume.mock.calls[0][0]).searchParams.get("startIndex")).toBe("2");
    // Changes since the backfill began are the next incremental run's job.
    expect(second.getState()?.last_modified_through).toBe(NOW.toISOString());
  });

  it("runs incrementally from the last successful run once backfilled", async () => {
    const { writer, getState } = memoryWriter({
      backfill_started_at: "2026-10-01T00:00:00Z",
      backfill_next_index: null,
      backfill_completed_at: "2026-10-01T01:00:00Z",
      last_success_at: "2026-10-31T02:50:00Z",
      last_modified_through: "2026-10-31T02:50:00Z",
      cve_count: 1,
    });
    const fetchImpl = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(pageResponse(0, 2001, Array.from({ length: 2000 }, (_, i) => cve(i))))
      .mockResolvedValueOnce(pageResponse(2000, 2001, [cve(9999)]));
    const sleep = vi.fn(async () => {});
    const summary = await syncCveIndex(writer, { now: NOW, fetchImpl, sleep, apiKey: "k" });
    expect(summary).toMatchObject({ mode: "incremental", pages: 2, cves: 2001, completed: true });
    const url = new URL(fetchImpl.mock.calls[0][0]);
    expect(url.searchParams.get("lastModStartDate")).toBe("2026-10-31T01:50:00.000+00:00");
    expect(sleep).toHaveBeenCalledWith(700);
    expect(getState()).toMatchObject({ last_modified_through: NOW.toISOString(), last_success_at: NOW.toISOString() });
  });

  it("records the error and leaves the window unmoved when NVD fails", async () => {
    const before = {
      backfill_started_at: "2026-10-01T00:00:00Z",
      backfill_next_index: null,
      backfill_completed_at: "2026-10-01T01:00:00Z",
      last_success_at: "2026-10-31T02:50:00Z",
      last_modified_through: "2026-10-31T02:50:00Z",
      cve_count: 1,
    };
    const { writer, getState } = memoryWriter(before);
    const fetchImpl = vi.fn<FetchLike>().mockResolvedValue(new Response("", { status: 404 }));
    await expect(syncCveIndex(writer, { now: NOW, fetchImpl, sleep: async () => {} })).rejects.toThrow("HTTP 404");
    expect(getState()).toMatchObject({ last_modified_through: before.last_modified_through, last_success_at: before.last_success_at, last_error: "NVD answered HTTP 404" });
  });

  it("still throws the original error when recording it fails too", async () => {
    const { writer } = memoryWriter(null);
    writer.writeState = async () => {
      throw new Error("db down");
    };
    await expect(syncCveIndex(writer, { now: NOW, fetchImpl: vi.fn<FetchLike>(), sleep: async () => {} })).rejects.toThrow("db down");
    const w2 = memoryWriter(null).writer;
    let calls = 0;
    w2.writeState = async () => {
      if (calls++ > 0) throw new Error("state write failed");
    };
    await expect(
      syncCveIndex(w2, { now: NOW, fetchImpl: vi.fn<FetchLike>().mockResolvedValue(new Response("", { status: 400 })), sleep: async () => {} })
    ).rejects.toThrow("HTTP 400");
  });
});

describe("supabaseCveIndexWriter", () => {
  function fakeClient(responses: { state?: unknown; stateError?: string; rpcError?: string; upsertError?: string; count?: number | null; countError?: string }) {
    const rpc = vi.fn(async () => ({ error: responses.rpcError ? { message: responses.rpcError } : null }));
    const upsert = vi.fn(async () => ({ error: responses.upsertError ? { message: responses.upsertError } : null }));
    const client = {
      rpc,
      from(table: string) {
        if (table === "cve_index_state") {
          return {
            select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: responses.state ?? null, error: responses.stateError ? { message: responses.stateError } : null }) }) }),
            upsert,
          };
        }
        return { select: async () => ({ count: responses.count ?? null, error: responses.countError ? { message: responses.countError } : null }) };
      },
    };
    return { client: client as unknown as SupabaseClient, rpc, upsert };
  }

  it("sends entries to the batch RPC, flattening each record", async () => {
    const { client, rpc } = fakeClient({});
    const entry = toIndexEntry(REGRESSHION)!;
    await supabaseCveIndexWriter(client).writeEntries([entry, { cve_id: "CVE-2023-9999", rejected: true }]);
    const [[name, args]] = rpc.mock.calls as unknown as Array<[string, { p_entries: Array<Record<string, unknown>> }]>;
    expect(name).toBe("replace_cve_batch");
    expect(args.p_entries[0]).toMatchObject({ cve_id: "CVE-2024-6387", rejected: false, cvss_score: 8.1, matches: expect.any(Array) });
    expect(args.p_entries[1]).toEqual({ cve_id: "CVE-2023-9999", rejected: true });
  });

  it("reads and upserts the single state row, and counts records", async () => {
    const { client, upsert } = fakeClient({ state: { backfill_completed_at: null }, count: 7 });
    const writer = supabaseCveIndexWriter(client);
    expect(await writer.readState()).toEqual({ backfill_completed_at: null });
    await writer.writeState({ last_run_at: "x", last_error: null });
    expect(upsert).toHaveBeenCalledWith({ id: true, last_run_at: "x", last_error: null }, { onConflict: "id" });
    expect(await writer.countRecords()).toBe(7);
    expect(await supabaseCveIndexWriter(fakeClient({}).client).countRecords()).toBe(0);
    expect(await supabaseCveIndexWriter(fakeClient({}).client).readState()).toBeNull();
  });

  it("throws on every failed write or read", async () => {
    const writer = supabaseCveIndexWriter(fakeClient({ stateError: "a", rpcError: "b", upsertError: "c", countError: "d" }).client);
    await expect(writer.readState()).rejects.toThrow("cve_index_state read failed: a");
    await expect(writer.writeEntries([])).rejects.toThrow("replace_cve_batch failed: b");
    await expect(writer.writeState({ last_run_at: "x", last_error: null })).rejects.toThrow("cve_index_state write failed: c");
    await expect(writer.countRecords()).rejects.toThrow("cve_records count failed: d");
  });
});

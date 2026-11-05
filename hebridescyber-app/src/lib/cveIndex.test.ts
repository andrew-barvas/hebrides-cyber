import { describe, it, expect, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  parseCpe,
  compareVersions,
  versionInCriterion,
  matchCriteria,
  describeCriterion,
  indexUnusableReason,
  isVersionBounded,
  createCveIndex,
  memoryCveIndexStore,
  supabaseCveIndexStore,
  type CveMatchRow,
  type CveRecordRow,
  type CveIndexState,
  type CveIndexStore,
} from "./cveIndex";

const NOW = new Date("2026-11-01T12:00:00Z");
const FRESH: CveIndexState = {
  backfill_completed_at: "2026-10-01T00:00:00Z",
  last_success_at: "2026-11-01T03:00:00Z",
  last_modified_through: "2026-11-01T02:50:00Z",
  cve_count: 300_000,
};

function row(over: Partial<CveMatchRow>): CveMatchRow {
  return {
    cve_id: "CVE-2024-6387",
    part: "a",
    vendor: "openbsd",
    product: "openssh",
    exact_version: null,
    any_update: false,
    start_including: null,
    start_excluding: null,
    end_including: null,
    end_excluding: null,
    conditional: false,
    criteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
    ...over,
  };
}

// Shaped like NVD's CVE-2024-6387 (regreSSHion) criteria: < 4.4, 4.4 exactly,
// 8.5p1 exactly, and 8.6 through 9.8 inclusive (9.8p1 is the fix).
const REGRESSHION: CveMatchRow[] = [
  row({ end_excluding: "4.4" }),
  row({ exact_version: "4.4", criteria: "cpe:2.3:a:openbsd:openssh:4.4:-:*:*:*:*:*:*" }),
  row({ exact_version: "8.5p1", criteria: "cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*" }),
  row({ start_including: "8.6", end_including: "9.8" }),
];
const RECORDS: CveRecordRow[] = [
  {
    cve_id: "CVE-2024-6387",
    cvss_score: 8.1,
    cvss_version: "3.1",
    cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    summary: "A signal handler race condition was found in OpenSSH's server (sshd).",
    published_at: "2024-07-01T13:15:00.000Z",
    last_modified_at: "2025-01-01T00:00:00.000Z",
  },
];

describe("parseCpe", () => {
  it("reads nmap's CPE 2.2 URIs", () => {
    expect(parseCpe("cpe:/a:openbsd:openssh:8.9p1")).toEqual({ part: "a", vendor: "openbsd", product: "openssh", version: "8.9p1" });
    expect(parseCpe("cpe:/a:apache:http_server")).toEqual({ part: "a", vendor: "apache", product: "http_server", version: null });
    expect(parseCpe("cpe:/o:canonical:ubuntu_linux")).toMatchObject({ part: "o", version: null });
  });

  it("reads NVD's CPE 2.3 strings, folding a named update into the version", () => {
    expect(parseCpe("cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*")).toMatchObject({ version: "8.5p1" });
    expect(parseCpe("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")).toMatchObject({ version: null });
    expect(parseCpe("cpe:2.3:a:joomla:joomla\\!:4.2.7:*:*:*:*:*:*:*")).toMatchObject({ product: "joomla!", version: "4.2.7" });
  });

  it("decodes percent-escapes in 2.2 URIs and rejects non-CPEs", () => {
    expect(parseCpe("cpe:/a:joomla:joomla%21:4.2.7")).toMatchObject({ product: "joomla!" });
    expect(parseCpe("cpe:/a:bad:%E0%A4%A")).toBeNull();
    expect(parseCpe("not a cpe")).toBeNull();
    expect(parseCpe("cpe:/x:vendor:product")).toBeNull();
    expect(parseCpe("cpe:/a::product")).toBeNull();
  });
});

describe("compareVersions", () => {
  it("orders dotted numbers", () => {
    expect(compareVersions("2.4.49", "2.4.50")).toBe("lt");
    expect(compareVersions("2.4.50", "2.4.49")).toBe("gt");
    expect(compareVersions("2.4", "2.4.0")).toBe("eq");
    expect(compareVersions("2.4.49", "2.4")).toBe("gt");
  });

  it("orders OpenSSH's portable suffix after its base release", () => {
    expect(compareVersions("9.8p1", "9.8")).toBe("gt");
    expect(compareVersions("9.8", "9.8p1")).toBe("lt");
    expect(compareVersions("8.9p1", "9.8")).toBe("lt");
    expect(compareVersions("9.3p1", "9.3p2")).toBe("lt");
  });

  it("orders OpenSSL-style single letters but not words", () => {
    expect(compareVersions("1.0.2k", "1.0.2u")).toBe("lt");
    expect(compareVersions("2.0.0", "2.0.0rc1")).toBe("unknown");
    expect(compareVersions("2.0.0beta", "2.0.0rc")).toBe("unknown");
    expect(compareVersions("1.2a", "1.2.3")).toBe("unknown");
  });

  it("can't place a partial version or an unorderable scheme", () => {
    expect(compareVersions("2.4", "2.4.49")).toBe("unknown");
    expect(compareVersions("r22", "1.0")).toBe("unknown");
    expect(compareVersions("1.0", "99999999999999999999")).toBe("unknown");
  });
});

describe("versionInCriterion / matchCriteria", () => {
  it("matches regreSSHion's ranges the way NVD means them", () => {
    const hit = (v: string) => matchCriteria(v, REGRESSHION).matched.has("CVE-2024-6387");
    expect(hit("8.9p1")).toBe(true);
    expect(hit("9.8")).toBe(true);
    expect(hit("8.5p1")).toBe(true);
    expect(hit("3.9p1")).toBe(true);
    expect(hit("9.8p1")).toBe(false); // the fix
    expect(hit("7.4")).toBe(false);
    expect(hit("8.5")).toBe(false);
    expect(hit("4.4p1")).toBe(false); // 4.4 with update "-" names no portable release
  });

  it("an exact criterion with any update covers that version's portable releases", () => {
    expect(versionInCriterion("7.4p1", row({ exact_version: "7.4", any_update: true }))).toBe("in");
    expect(versionInCriterion("7.4p1", row({ exact_version: "7.4" }))).toBe("out");
  });

  it("never matches an unbounded criterion", () => {
    const unbounded = row({});
    expect(isVersionBounded(unbounded)).toBe(false);
    expect(versionInCriterion("1.0", unbounded)).toBe("out");
  });

  it("reports a CVE it can't place as undetermined, not matched", () => {
    const r = matchCriteria("2.4", [row({ cve_id: "CVE-2021-41773", vendor: "apache", product: "http_server", exact_version: "2.4.49" })]);
    expect(r.matched.size).toBe(0);
    expect([...r.undetermined]).toEqual(["CVE-2021-41773"]);
    const both = matchCriteria("8.9p1", [row({ start_including: "8.6", end_including: "9.8" }), row({ exact_version: "8.9p1rc1" })]);
    expect(both.undetermined.size).toBe(0);
  });

  it("prefers an unconditional criterion over a conditional one for the same CVE", () => {
    const r = matchCriteria("8.9p1", [row({ end_including: "9.8", conditional: true }), row({ start_including: "8.6", end_including: "9.8" })]);
    expect(r.matched.get("CVE-2024-6387")?.conditional).toBe(false);
  });

  it("checks every bound kind", () => {
    expect(versionInCriterion("2.0", row({ start_excluding: "2.0" }))).toBe("out");
    expect(versionInCriterion("2.1", row({ start_excluding: "2.0", end_excluding: "3.0" }))).toBe("in");
    expect(versionInCriterion("3.0", row({ end_excluding: "3.0" }))).toBe("out");
    expect(versionInCriterion("3.1", row({ end_including: "3.0" }))).toBe("out");
    expect(versionInCriterion("1.9", row({ start_including: "2.0" }))).toBe("out");
    expect(versionInCriterion("2", row({ start_including: "2.0.1" }))).toBe("unknown");
    expect(versionInCriterion("2.0.0", row({ exact_version: "2.0.0rc1" }))).toBe("unknown");
  });

  it("describes a criterion's range for evidence", () => {
    expect(describeCriterion(row({ start_including: "8.6", end_including: "9.8" }))).toBe(">= 8.6, <= 9.8");
    expect(describeCriterion(row({ start_excluding: "1", end_excluding: "2" }))).toBe("> 1, < 2");
    expect(describeCriterion(row({ exact_version: "7.4", any_update: true }))).toBe("7.4 (any update)");
    expect(describeCriterion(row({ exact_version: "8.5p1" }))).toBe("8.5p1");
  });
});

describe("indexUnusableReason", () => {
  it("accepts a fresh, backfilled index", () => {
    expect(indexUnusableReason(FRESH, NOW)).toBeNull();
  });

  it("refuses a missing, half-built, never-succeeded or stale index", () => {
    expect(indexUnusableReason(null, NOW)).toMatch(/never been built/);
    expect(indexUnusableReason({ ...FRESH, backfill_completed_at: null }, NOW)).toMatch(/first full build/);
    expect(indexUnusableReason({ ...FRESH, last_success_at: null }, NOW)).toMatch(/no successful sync/);
    expect(indexUnusableReason({ ...FRESH, last_success_at: "2026-10-20T00:00:00Z" }, NOW)).toMatch(/stale: last synced 12 days/);
  });
});

describe("createCveIndex", () => {
  const store = () => memoryCveIndexStore({ state: FRESH, matches: REGRESSHION, records: RECORDS });

  it("looks up a CPE and returns matches with their evidence", async () => {
    const result = await createCveIndex(store(), { now: NOW }).lookup({ cpe: "cpe:/a:openbsd:openssh:8.9p1" });
    expect(result.status).toBe("checked");
    if (result.status !== "checked") return;
    expect(result.cpe).toBe("cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*");
    expect(result.indexedThrough).toBe(FRESH.last_modified_through);
    expect(result.matches).toEqual([
      expect.objectContaining({
        cveId: "CVE-2024-6387",
        cvssScore: 8.1,
        cvssVersion: "3.1",
        range: ">= 8.6, <= 9.8",
        matchedCriteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
        conditional: false,
      }),
    ]);
  });

  it("accepts vendor, product and version, and an override version for a CPE", async () => {
    const index = createCveIndex(store(), { now: NOW });
    const byName = await index.lookup({ vendor: "OpenBSD", product: "OpenSSH", version: "9.8p1" });
    expect(byName).toMatchObject({ status: "checked", matches: [] });
    const overridden = await index.lookup({ cpe: "cpe:/a:openbsd:openssh", version: "8.9p1" });
    expect(overridden.status === "checked" && overridden.matches.length).toBe(1);
    expect(await index.lookup({ cpe: "cpe:/a:openbsd:openssh:8.9p1", version: null })).toMatchObject({ status: "version_unknown" });
  });

  it("never turns a missing or unorderable version into a CVE", async () => {
    const index = createCveIndex(store(), { now: NOW });
    expect(await index.lookup({ cpe: "cpe:/a:apache:http_server" })).toEqual({ status: "version_unknown", cpe: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*" });
    expect(await index.lookup({ vendor: "f5", product: "nginx", version: "r22" })).toMatchObject({ status: "unordered_version", version: "r22" });
    expect(await index.lookup({ cpe: "garbage" })).toMatchObject({ status: "error" });
  });

  it("queries NVD's current name for a product nmap names the old way", async () => {
    const nginx = [row({ cve_id: "CVE-2021-23017", vendor: "f5", product: "nginx", start_including: "0.6.18", end_excluding: "1.20.1" })];
    const index = createCveIndex(memoryCveIndexStore({ state: FRESH, matches: nginx, records: [] }), { now: NOW });
    const result = await index.lookup({ cpe: "cpe:/a:igor_sysoev:nginx:1.18.0" });
    expect(result.status === "checked" && result.matches.map((m) => m.cveId)).toEqual(["CVE-2021-23017"]);
    // Unscored record: still reported, with a null score.
    expect(result.status === "checked" && result.matches[0].cvssScore).toBeNull();
  });

  it("only matches criteria of the same CPE part", async () => {
    const os = [row({ part: "o", exact_version: "8.9p1" })];
    const result = await createCveIndex(memoryCveIndexStore({ state: FRESH, matches: os, records: [] }), { now: NOW }).lookup({ cpe: "cpe:/a:openbsd:openssh:8.9p1" });
    expect(result).toMatchObject({ status: "checked", matches: [] });
  });

  it("is an error, never clean, when the index is unusable or a read fails", async () => {
    const stale = createCveIndex(memoryCveIndexStore({ state: null, matches: REGRESSHION, records: RECORDS }), { now: NOW });
    expect(await stale.lookup({ cpe: "cpe:/a:openbsd:openssh:8.9p1" })).toMatchObject({ status: "error", note: expect.stringMatching(/never been built/) });

    const failing: CveIndexStore = { ...store(), readMatches: () => Promise.reject(new Error("relation does not exist")) };
    expect(await createCveIndex(failing, { now: NOW }).lookup({ cpe: "cpe:/a:openbsd:openssh:8.9p1" })).toEqual({
      status: "error",
      note: "CVE index read failed: relation does not exist",
    });
  });

  it("reads the state once and each product's criteria once per instance", async () => {
    const s = store();
    const readState = vi.spyOn(s, "readState");
    const readMatches = vi.spyOn(s, "readMatches");
    const readRecords = vi.spyOn(s, "readRecords");
    const index = createCveIndex(s, { now: NOW });
    await index.lookup({ cpe: "cpe:/a:openbsd:openssh:8.9p1" });
    await index.lookup({ cpe: "cpe:/a:openbsd:openssh:9.7p1" });
    expect(readState).toHaveBeenCalledTimes(1);
    expect(readMatches).toHaveBeenCalledTimes(1);
    expect(readRecords).toHaveBeenCalledTimes(1);
  });

  it("drops rows that aren't a CVE id and sorts by score", async () => {
    const rows = [row({ cve_id: "GHSA-xxxx", end_including: "9.8" }), row({ cve_id: "CVE-2023-0001", end_including: "9.8" }), ...REGRESSHION];
    const result = await createCveIndex(memoryCveIndexStore({ state: FRESH, matches: rows, records: RECORDS }), { now: NOW }).lookup({
      cpe: "cpe:/a:openbsd:openssh:8.9p1",
    });
    expect(result.status === "checked" && result.matches.map((m) => m.cveId)).toEqual(["CVE-2024-6387", "CVE-2023-0001"]);
  });
});

// A chainable stand-in for the bits of supabase-js the store uses.
function fakeClient(tables: Record<string, Array<{ data: unknown; error: { message: string } | null }>>) {
  const calls: Array<{ table: string; ops: Array<[string, unknown[]]> }> = [];
  const client = {
    from(table: string) {
      const call = { table, ops: [] as Array<[string, unknown[]]> };
      calls.push(call);
      const builder: Record<string, unknown> = {};
      for (const op of ["select", "eq", "order", "range", "in"]) {
        builder[op] = (...args: unknown[]) => {
          call.ops.push([op, args]);
          return builder;
        };
      }
      const next = () => Promise.resolve(tables[table].shift() ?? { data: null, error: { message: "no more responses" } });
      builder.maybeSingle = next;
      builder.then = (resolve: (v: unknown) => void, reject: (e: unknown) => void) => next().then(resolve, reject);
      return builder;
    },
  };
  return { client: client as unknown as SupabaseClient, calls };
}

describe("supabaseCveIndexStore", () => {
  it("reads the state row and pages through a product's criteria", async () => {
    const page = Array.from({ length: 1000 }, () => row({}));
    const { client, calls } = fakeClient({
      cve_index_state: [{ data: FRESH, error: null }],
      cve_cpe_matches: [
        { data: page, error: null },
        { data: [row({})], error: null },
      ],
    });
    const store = supabaseCveIndexStore(client);
    expect(await store.readState()).toEqual(FRESH);
    expect(await store.readMatches("openbsd", "openssh")).toHaveLength(1001);
    const ranges = calls.filter((c) => c.table === "cve_cpe_matches").map((c) => c.ops.find(([op]) => op === "range")?.[1]);
    expect(ranges).toEqual([
      [0, 999],
      [1000, 1999],
    ]);
  });

  it("reads records in chunks and coerces numeric scores", async () => {
    const ids = Array.from({ length: 160 }, (_, i) => `CVE-2024-${String(10000 + i)}`);
    const { client, calls } = fakeClient({
      cve_records: [
        { data: [{ ...RECORDS[0], cvss_score: "8.1" }], error: null },
        { data: [{ ...RECORDS[0], cve_id: "CVE-2024-0002", cvss_score: null }], error: null },
      ],
    });
    const recs = await supabaseCveIndexStore(client).readRecords(ids);
    expect(recs.map((r) => r.cvss_score)).toEqual([8.1, null]);
    expect(calls).toHaveLength(2);
  });

  it("throws on a failed read, which lookup reports as an error", async () => {
    const { client } = fakeClient({
      cve_index_state: [{ data: null, error: { message: "relation \"cve_index_state\" does not exist" } }],
      cve_cpe_matches: [{ data: null, error: { message: "boom" } }],
      cve_records: [{ data: null, error: { message: "boom" } }],
    });
    const store = supabaseCveIndexStore(client);
    await expect(store.readState()).rejects.toThrow(/does not exist/);
    await expect(store.readMatches("a", "b")).rejects.toThrow("boom");
    await expect(store.readRecords(["CVE-2024-0001"])).rejects.toThrow("boom");
  });

  it("treats an absent state row as never built", async () => {
    const { client } = fakeClient({ cve_index_state: [{ data: null, error: null }] });
    expect(await supabaseCveIndexStore(client).readState()).toBeNull();
  });
});

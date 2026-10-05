import { describe, it, expect, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  CSV_HEADER,
  DEFAULT_FILTERS,
  MAX_OPEN_ROWS,
  applyFilters,
  buildFacets,
  buildFindingRows,
  categoryOfCheck,
  checkBaseOf,
  compareFindings,
  findingsToCsv,
  groupFindings,
  humaniseCheckBase,
  loadFindingsView,
  paginate,
  parseFindingsQuery,
  type FindingFilters,
  type FindingRow,
  type HostDetail,
  type LifecycleOpenRow,
} from "./findingsView";
import { DEFAULT_SLA_POLICY } from "./slaMonitoring";
import { buildTriageIndex, EMPTY_TRIAGE_INDEX, type TriageDbRow } from "./findingTriage";

vi.mock("./slaAlerts", () => ({ hasSlaAccess: vi.fn() }));
import { hasSlaAccess } from "./slaAlerts";

const NOW = new Date("2026-10-05T12:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

const life = (host: string, checkId: string, severity: string, age: number, extra: Partial<LifecycleOpenRow> = {}): LifecycleOpenRow => ({
  id: `${host}-${checkId}`, target_host: host, check_id: checkId, severity, title: `T ${checkId}`,
  first_seen_at: daysAgo(age), last_seen_at: daysAgo(0), resolved_at: null, ...extra,
});

const triageRow = (host: string, checkId: string, state: TriageDbRow["state"], expires: string | null = null): TriageDbRow => ({
  id: "t", owner: "o", target_host: host, check_id: checkId, state, reason: "because", expires_at: expires,
  created_by: null, created_at: daysAgo(1), updated_at: daysAgo(1),
});

function row(over: Partial<FindingRow> = {}): FindingRow {
  return {
    key: "a.example headers.hsts", host: "a.example", checkId: "headers.hsts", checkBase: "headers.hsts", category: "headers",
    severity: "medium", title: "Missing HSTS", detail: null, firstSeenAt: daysAgo(10), ageDays: 10, slaState: null, slaDueAt: null,
    knownExploited: false, ransomware: false, epss: null, cveIds: [], scanId: null, triage: null, ...over,
  };
}

describe("checkBaseOf / categoryOfCheck / humaniseCheckBase", () => {
  it("splits identity from instance key and category", () => {
    expect(checkBaseOf("script-inventory.unreviewed:https://cdn.x")).toBe("script-inventory.unreviewed");
    expect(categoryOfCheck("headers.hsts-missing")).toBe("headers");
    expect(categoryOfCheck("sast.rule:abc")).toBe("sast");
    expect(categoryOfCheck("")).toBe("other");
  });
  it("humanises", () => {
    expect(humaniseCheckBase("headers.hsts-missing")).toBe("Headers hsts missing");
    expect(humaniseCheckBase("")).toBe("");
  });
});

describe("buildFindingRows", () => {
  const detail = new Map<string, HostDetail>([
    [
      "a.example",
      {
        scanId: "scan-a",
        findings: [
          { checkId: "nuclei.cve-1", detail: "x".repeat(900), cveIds: ["CVE-2021-1"], threatIntel: { knownExploited: true, ransomware: true, epss: 0.7 } },
          { checkId: "nuclei.cve-1", detail: "duplicate ignored" },
          { detail: "no check id" },
          { checkId: "headers.hsts", threatIntel: {} },
        ],
      },
    ],
  ]);

  it("joins lifecycle with the latest scan's detail and threat intel", () => {
    const rows = buildFindingRows([life("A.example", "nuclei.cve-1", "critical", 20)], detail, EMPTY_TRIAGE_INDEX, DEFAULT_SLA_POLICY, NOW);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      host: "a.example", checkBase: "nuclei.cve-1", category: "nuclei", severity: "critical", ageDays: 20, scanId: "scan-a",
      knownExploited: true, ransomware: true, epss: 0.7, cveIds: ["CVE-2021-1"], slaState: "breached",
    });
    expect(rows[0].detail).toHaveLength(500);
  });

  it("keeps a finding the latest scan no longer carries, from its lifecycle row", () => {
    const rows = buildFindingRows([life("b.example", "tls.x", "high", 40, { last_scan_id: "old" })], detail, EMPTY_TRIAGE_INDEX, DEFAULT_SLA_POLICY, NOW);
    expect(rows[0]).toMatchObject({ detail: null, scanId: "old", knownExploited: false, epss: null, cveIds: [], slaState: "breached" });
    const noScan = buildFindingRows([life("b.example", "tls.x", "high", 1)], detail, EMPTY_TRIAGE_INDEX, null, NOW);
    expect(noScan[0].scanId).toBeNull();
    expect(noScan[0].slaState).toBeNull();
    expect(noScan[0].slaDueAt).toBeNull();
  });

  it("skips resolved rows, tolerates odd data and attaches only active triage", () => {
    const index = buildTriageIndex(
      [triageRow("a.example", "headers.hsts", "snoozed", "2026-11-01T00:00:00Z"), triageRow("a.example", "dns.spf", "accepted_risk", "2026-01-01T00:00:00Z")],
      NOW
    );
    const rows = buildFindingRows(
      [
        life("a.example", "headers.hsts", "weird", 3),
        life("a.example", "dns.spf", "low", 3),
        life("a.example", "old", "low", 3, { resolved_at: daysAgo(1) }),
        life("a.example", "bad.date", "low", 0, { first_seen_at: "not a date" }),
      ],
      detail,
      index,
      DEFAULT_SLA_POLICY,
      NOW
    );
    expect(rows.map((r) => r.checkId)).toEqual(["headers.hsts", "dns.spf", "bad.date"]);
    expect(rows[0].severity).toBe("info");
    expect(rows[0].triage).toEqual({ state: "snoozed", reason: "because", expiresAt: "2026-11-01T00:00:00Z" });
    expect(rows[1].triage).toBeNull(); // expired
    expect(rows[2].ageDays).toBe(0);
  });
});

describe("applyFilters", () => {
  const rows = [
    row({ key: "1", host: "a.example", severity: "critical", category: "nuclei", knownExploited: true, epss: 0.8, ageDays: 40, slaState: "breached" }),
    row({ key: "2", host: "b.example", severity: "medium", category: "headers", epss: 0.05, ageDays: 5, slaState: "on_track" }),
    row({ key: "3", host: "b.example", severity: "low", category: "dns", ageDays: 100, triage: { state: "snoozed", reason: "r", expiresAt: null } }),
    row({ key: "4", host: "a.example", severity: "high", category: "dns", ageDays: 1, triage: { state: "accepted_risk", reason: "r", expiresAt: null } }),
  ];
  const keys = (f: Partial<FindingFilters>) => applyFilters(rows, { ...DEFAULT_FILTERS, ...f }).map((r) => r.key);

  it("defaults to untriaged findings", () => expect(keys({})).toEqual(["1", "2"]));
  it("filters by site", () => expect(keys({ site: "b.example", triage: "all" })).toEqual(["2", "3"]));
  it("filters by severity", () => expect(keys({ severities: ["critical", "medium"] })).toEqual(["1", "2"]));
  it("filters by KEV", () => expect(keys({ kev: true })).toEqual(["1"]));
  it("filters by EPSS, ignoring findings with no score", () => {
    expect(keys({ epssMin: 0.5 })).toEqual(["1"]);
    expect(keys({ epssMin: 0.01 })).toEqual(["1", "2"]);
  });
  it("filters by category", () => expect(keys({ category: "headers" })).toEqual(["2"]));
  it("filters by SLA state and age", () => {
    expect(keys({ sla: "breached" })).toEqual(["1"]);
    expect(keys({ minAgeDays: 30, triage: "all" })).toEqual(["1", "3"]);
  });
  it("filters by triage state", () => {
    expect(keys({ triage: "triaged" })).toEqual(["3", "4"]);
    expect(keys({ triage: "snoozed" })).toEqual(["3"]);
    expect(keys({ triage: "accepted_risk" })).toEqual(["4"]);
    expect(keys({ triage: "false_positive" })).toEqual([]);
    expect(keys({ triage: "all" })).toHaveLength(4);
  });
});

describe("parseFindingsQuery", () => {
  it("defaults", () => {
    expect(parseFindingsQuery({})).toEqual({ filters: DEFAULT_FILTERS, view: "grouped", page: 1, pageSize: 50, format: "json" });
  });
  it("reads every parameter", () => {
    const q = parseFindingsQuery({
      site: " Shop.Example ", severity: "High,critical,bogus,high", kev: "1", epssMin: "0.25", category: "DNS", triage: "snoozed",
      sla: "due_soon", minAgeDays: "30", view: "rows", page: "3", pageSize: "20", format: "csv",
    });
    expect(q).toEqual({
      filters: { site: "shop.example", severities: ["high", "critical"], kev: true, epssMin: 0.25, category: "dns", triage: "snoozed", sla: "due_soon", minAgeDays: 30 },
      view: "rows", page: 3, pageSize: 20, format: "csv",
    });
  });
  it("takes the first of repeated parameters and falls back on junk", () => {
    const q = parseFindingsQuery({ kev: "no", epssMin: "7", triage: "nope", sla: "x", minAgeDays: "-1", page: "0", pageSize: "0", severity: "" });
    expect(q.filters).toEqual(DEFAULT_FILTERS);
    expect(q.page).toBe(1);
    expect(q.pageSize).toBe(50);
    expect(parseFindingsQuery({ epssMin: "abc" }).filters.epssMin).toBeNull();
    expect(parseFindingsQuery({ pageSize: "9999" }).pageSize).toBe(100);
    expect(parseFindingsQuery({ site: ["a.example"] }).filters.site).toBe("a.example");
  });
});

describe("compareFindings / groupFindings", () => {
  const rows = [
    row({ key: "a", host: "a.example", checkId: "headers.hsts", checkBase: "headers.hsts", title: "Missing HSTS", severity: "medium" }),
    row({ key: "b", host: "b.example", checkId: "headers.hsts", checkBase: "headers.hsts", title: "Missing HSTS", severity: "medium", ageDays: 90, firstSeenAt: daysAgo(90) }),
    row({ key: "c", host: "c.example", checkId: "headers.hsts", checkBase: "headers.hsts", title: "Missing HSTS", severity: "medium", epss: 0.3 }),
    row({ key: "d", host: "a.example", checkId: "script-inventory.unreviewed:x", checkBase: "script-inventory.unreviewed", category: "script-inventory", title: "Script x", severity: "low" }),
    row({ key: "e", host: "a.example", checkId: "script-inventory.unreviewed:y", checkBase: "script-inventory.unreviewed", category: "script-inventory", title: "Script y", severity: "low" }),
    row({ key: "f", host: "a.example", checkId: "nuclei.cve", checkBase: "nuclei.cve", category: "nuclei", title: "CVE", severity: "critical", knownExploited: true }),
  ];

  it("orders by severity, KEV, EPSS, age then name", () => {
    const sorted = [...rows].sort(compareFindings).map((r) => r.key);
    expect(sorted).toEqual(["f", "c", "b", "a", "d", "e"]);
    expect(compareFindings(row({ host: "a" }), row({ host: "b" }))).toBeLessThan(0);
    expect(compareFindings(row({ checkId: "a" }), row({ checkId: "b" }))).toBeLessThan(0);
  });

  it("groups by checkId base: 'missing HSTS on 3 sites'", () => {
    const groups = groupFindings(rows);
    expect(groups.map((g) => g.key)).toEqual(["nuclei.cve", "headers.hsts", "script-inventory.unreviewed"]);
    const hsts = groups[1];
    expect(hsts).toMatchObject({ label: "Missing HSTS", count: 3, siteCount: 3, sites: ["a.example", "b.example", "c.example"], maxEpss: 0.3, knownExploited: false, severity: "medium" });
    expect(hsts.oldestFirstSeenAt).toBe(daysAgo(90));
    expect(hsts.rows.map((r) => r.key)).toEqual(["c", "b", "a"]);
    expect(groups[0]).toMatchObject({ knownExploited: true, maxEpss: null });
  });

  it("names a group by its check id when its rows' titles differ, and orders ties by size", () => {
    const groups = groupFindings(rows);
    expect(groups[2].label).toBe("Script inventory unreviewed");
    const tied = groupFindings([
      row({ key: "1", checkBase: "x.a", checkId: "x.a" }),
      row({ key: "2", checkBase: "x.b", checkId: "x.b", host: "b.example" }),
      row({ key: "3", checkBase: "x.b", checkId: "x.b", host: "c.example" }),
      row({ key: "4", checkBase: "x.c", checkId: "x.c", host: "c.example" }),
      row({ key: "5", checkBase: "x.c", checkId: "x.c", host: "c.example", severity: "medium" }),
    ]);
    expect(tied.map((g) => g.key)).toEqual(["x.b", "x.c", "x.a"]);
    expect(groupFindings([])).toEqual([]);
  });
});

describe("paginate", () => {
  const items = Array.from({ length: 25 }, (_, i) => i);
  it("slices pages", () => {
    expect(paginate(items, 2, 10)).toEqual({ items: [10, 11, 12, 13, 14, 15, 16, 17, 18, 19], page: 2, pageSize: 10, total: 25, pageCount: 3 });
  });
  it("clamps pages and sizes", () => {
    expect(paginate(items, 99, 10).page).toBe(3);
    expect(paginate(items, 99, 10).items).toEqual([20, 21, 22, 23, 24]);
    expect(paginate(items, -4, 10).page).toBe(1);
    expect(paginate(items, 1, 0).pageSize).toBe(1);
    expect(paginate(items, 1, 5000).pageSize).toBe(100);
    expect(paginate([], 1, 10)).toEqual({ items: [], page: 1, pageSize: 10, total: 0, pageCount: 1 });
  });
});

describe("buildFacets", () => {
  it("counts untriaged findings for the filter bar", () => {
    const facets = buildFacets([
      row({ host: "b.example", category: "dns", severity: "high", knownExploited: true }),
      row({ host: "a.example", category: "headers" }),
      row({ host: "a.example", category: "headers", severity: "low" }),
      row({ host: "c.example", triage: { state: "snoozed", reason: "r", expiresAt: null } }),
    ]);
    expect(facets.sites).toEqual([{ value: "a.example", count: 2 }, { value: "b.example", count: 1 }]);
    expect(facets.categories).toEqual([{ value: "dns", count: 1 }, { value: "headers", count: 2 }]);
    expect(facets.severities).toEqual({ critical: 0, high: 1, medium: 1, low: 1, info: 0 });
    expect(facets.knownExploited).toBe(1);
  });
});

describe("findingsToCsv", () => {
  it("writes a header and CRLF rows", () => {
    const csv = findingsToCsv([
      row({ epss: 0.5, cveIds: ["CVE-1", "CVE-2"], slaState: "breached", slaDueAt: "2026-10-01T00:00:00Z", knownExploited: true, triage: { state: "snoozed", reason: "later, ok", expiresAt: "2026-11-01T00:00:00Z" } }),
      row({ key: "2", title: 'Has "quotes"' }),
    ]);
    const lines = csv.split("\r\n");
    expect(lines[0]).toBe(CSV_HEADER.join(","));
    expect(lines[1]).toBe(
      `a.example,medium,Missing HSTS,headers.hsts,headers,${daysAgo(10)},10,breached,2026-10-01T00:00:00Z,yes,0.5,CVE-1 CVE-2,snoozed,"later, ok",2026-11-01T00:00:00Z`
    );
    expect(lines[2]).toContain('"Has ""quotes"""');
    expect(lines[2]).toContain(",no,,,,,");
    expect(csv.endsWith("\r\n")).toBe(true);
  });

  it("neutralises spreadsheet formulas in scanned text", () => {
    const csv = findingsToCsv([row({ title: "=HYPERLINK(\"http://evil\")", host: "+cmd", checkId: "@SUM(1)", triage: { state: "accepted_risk", reason: "-2+3", expiresAt: null } })]);
    const cells = csv.split("\r\n")[1];
    expect(cells).toContain(`"'=HYPERLINK(""http://evil"")"`);
    expect(cells.startsWith("'+cmd,")).toBe(true);
    expect(cells).toContain(",'@SUM(1),");
    expect(cells).toContain(",'-2+3,");
  });

  it("is just a header for no rows", () => expect(findingsToCsv([])).toBe(`${CSV_HEADER.join(",")}\r\n`));
});

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

type Res = { data: unknown; error: { code?: string; message: string } | null };
type Tables = {
  lifecycle: Res; triage: Res; policy: Res; scans: Res; results: Res;
};

function fakeClient(t: Tables): SupabaseClient {
  const from = (table: string) => {
    const res = (): Res =>
      ({ finding_lifecycle: t.lifecycle, finding_triage: t.triage, sla_policies: t.policy, scans: t.scans, scan_results: t.results })[table] as Res;
    const b: Record<string, unknown> = {};
    for (const m of ["select", "eq", "is", "order", "limit", "in"]) b[m] = () => b;
    b.maybeSingle = () => Promise.resolve(res());
    b.then = (resolve: (v: unknown) => unknown) => Promise.resolve(res()).then(resolve);
    return b;
  };
  return { from } as unknown as SupabaseClient;
}

const ok = (data: unknown): Res => ({ data, error: null });
const tables = (over: Partial<Tables> = {}): Tables => ({
  lifecycle: ok([life("a.example", "nuclei.cve-1", "critical", 20), life("b.example", "headers.hsts", "medium", 5)]),
  triage: ok([triageRow("b.example", "headers.hsts", "false_positive")]),
  policy: ok(null),
  scans: ok([
    { id: "s2", target_url: "https://a.example/", created_at: daysAgo(1) },
    { id: "s1", target_url: "https://a.example/", created_at: daysAgo(9) },
    { id: "s3", target_url: "https://other.example/", created_at: daysAgo(2) },
    { id: "s4", target_url: "not a url", created_at: daysAgo(2) },
  ]),
  results: ok([{ scan_id: "s2", findings: [{ checkId: "nuclei.cve-1", threatIntel: { knownExploited: true } }] }, { scan_id: "sx", findings: "bad" }]),
  ...over,
});

describe("loadFindingsView", () => {
  it("assembles rows with detail, triage and SLA", async () => {
    vi.mocked(hasSlaAccess).mockResolvedValue(true);
    const result = await loadFindingsView(fakeClient(tables()), "o", NOW);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data).toMatchObject({ available: true, triageAvailable: true, slaEnabled: true, detailComplete: true, truncated: false });
    const [a, b] = result.data.rows;
    expect(a).toMatchObject({ host: "a.example", knownExploited: true, scanId: "s2", slaState: "breached" });
    expect(b.triage?.state).toBe("false_positive");
  });

  it("uses the account's own SLA policy when it has one, and none without the plan", async () => {
    vi.mocked(hasSlaAccess).mockResolvedValue(true);
    const policy = { critical_days: 100, high_days: 100, medium_days: 100, low_days: 100, warn_days: 1, alerts_enabled: false };
    const withPolicy = await loadFindingsView(fakeClient(tables({ policy: ok(policy) })), "o", NOW);
    expect(withPolicy.ok && withPolicy.data.rows[0].slaState).toBe("on_track");
    vi.mocked(hasSlaAccess).mockResolvedValue(false);
    const without = await loadFindingsView(fakeClient(tables()), "o", NOW);
    expect(without.ok && without.data.slaEnabled).toBe(false);
    expect(without.ok && without.data.rows[0].slaState).toBeNull();
    vi.mocked(hasSlaAccess).mockRejectedValue(new Error("down"));
    const failed = await loadFindingsView(fakeClient(tables()), "o", NOW);
    expect(failed.ok && failed.data.slaEnabled).toBe(false);
  });

  it("reports unavailable before migration 043", async () => {
    vi.mocked(hasSlaAccess).mockResolvedValue(false);
    const result = await loadFindingsView(fakeClient(tables({ lifecycle: { data: null, error: { code: "42P01", message: "x" } } })), "o", NOW);
    expect(result).toEqual({ ok: true, data: { available: false, triageAvailable: false, slaEnabled: false, detailComplete: true, truncated: false, rows: [] } });
  });

  it("fails on any other lifecycle error", async () => {
    vi.mocked(hasSlaAccess).mockResolvedValue(false);
    const result = await loadFindingsView(fakeClient(tables({ lifecycle: { data: null, error: { code: "XX", message: "boom" } } })), "o", NOW);
    expect(result).toEqual({ ok: false, error: "Could not load findings" });
  });

  it("degrades to nothing triaged before migration 046, but fails on a real triage error", async () => {
    vi.mocked(hasSlaAccess).mockResolvedValue(false);
    const missing = await loadFindingsView(fakeClient(tables({ triage: { data: null, error: { code: "42P01", message: "x" } } })), "o", NOW);
    expect(missing.ok && missing.data.triageAvailable).toBe(false);
    expect(missing.ok && missing.data.rows.every((r) => r.triage === null)).toBe(true);
    const broken = await loadFindingsView(fakeClient(tables({ triage: { data: null, error: { code: "XX", message: "boom" } } })), "o", NOW);
    expect(broken).toEqual({ ok: false, error: "Could not load findings" });
  });

  it("keeps listing findings without detail when the scan lookups fail", async () => {
    vi.mocked(hasSlaAccess).mockResolvedValue(false);
    const scansFail = await loadFindingsView(fakeClient(tables({ scans: { data: null, error: { message: "x" } } })), "o", NOW);
    expect(scansFail.ok && scansFail.data.detailComplete).toBe(false);
    expect(scansFail.ok && scansFail.data.rows).toHaveLength(2);
    const resultsFail = await loadFindingsView(fakeClient(tables({ results: { data: null, error: { message: "x" } } })), "o", NOW);
    expect(resultsFail.ok && resultsFail.data.detailComplete).toBe(false);
  });

  it("is complete with no scans, no open findings or no matching hosts", async () => {
    vi.mocked(hasSlaAccess).mockResolvedValue(false);
    const none = await loadFindingsView(fakeClient(tables({ scans: ok(null) })), "o", NOW);
    expect(none.ok && none.data.detailComplete).toBe(true);
    const nothingOpen = await loadFindingsView(fakeClient(tables({ lifecycle: ok(null) })), "o", NOW);
    expect(nothingOpen.ok && nothingOpen.data.rows).toEqual([]);
    const noResults = await loadFindingsView(fakeClient(tables({ results: ok(null) })), "o", NOW);
    expect(noResults.ok && noResults.data.rows[0].scanId).toBeNull();
  });

  it("flags and trims an over-long list", async () => {
    vi.mocked(hasSlaAccess).mockResolvedValue(false);
    const many = Array.from({ length: MAX_OPEN_ROWS + 1 }, (_, i) => life("a.example", `x.${i}`, "low", 1));
    const result = await loadFindingsView(fakeClient(tables({ lifecycle: ok(many) })), "o", NOW);
    expect(result.ok && result.data.truncated).toBe(true);
    expect(result.ok && result.data.rows).toHaveLength(MAX_OPEN_ROWS);
  });
});

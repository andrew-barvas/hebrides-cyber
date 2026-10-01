import { describe, it, expect, vi } from "vitest";
import {
  backfillFirstSeen,
  dedupeFindings,
  findingSource,
  isCovered,
  planLifecycleSync,
  scanCoverage,
  syncFindingLifecycle,
  type CurrentFinding,
  type HistoricalScan,
  type LifecycleDbRow,
} from "./findingLifecycle";

const SCAN_AT = "2026-09-27T09:00:00.000Z";
const daysBefore = (n: number) => new Date(Date.parse(SCAN_AT) - n * 86_400_000).toISOString();

const PASSIVE = scanCoverage(undefined);
const FULL = scanCoverage({ nuclei: { status: "completed" }, deepTls: { status: "completed" }, sqlmap: { status: "error" } });

function existing(overrides: Partial<LifecycleDbRow> = {}): LifecycleDbRow {
  return {
    owner: "o1",
    target_host: "shop.example",
    check_id: "headers.csp-absent",
    severity: "high",
    title: "CSP missing",
    source: "base",
    first_seen_at: daysBefore(20),
    last_seen_at: daysBefore(1),
    last_scan_id: "prev-scan",
    resolved_at: null,
    sla_warned_at: null,
    sla_breach_notified_at: null,
    ...overrides,
  };
}

const f = (checkId: string, overrides: Partial<CurrentFinding> = {}): CurrentFinding => ({
  checkId,
  severity: "high",
  title: checkId,
  source: "base",
  ...overrides,
});

function plan(existingRows: LifecycleDbRow[], current: CurrentFinding[], coverage = PASSIVE, backfill?: Map<string, string>) {
  return planLifecycleSync({ owner: "o1", host: "shop.example", scanId: "scan-now", scanAt: SCAN_AT, existing: existingRows, current, coverage, backfill });
}

describe("coverage and source", () => {
  it("reads which extended tools completed, ignoring failures", () => {
    expect([...FULL.completedTools]).toEqual(["nuclei", "deeptls"]);
    expect(FULL.extendedRan).toBe(true);
    expect(PASSIVE.extendedRan).toBe(false);
    expect(scanCoverage({ cloudPosture: { status: "checked" } }).completedTools.has("cloudposture")).toBe(true);
  });

  it("maps a checkId namespace to the tool that produced it", () => {
    const keys = ["nuclei", "deepTls", "dependencyManifest", "apiSpecInjection"];
    expect(findingSource("nuclei.finding:x", true, keys)).toBe("nuclei");
    expect(findingSource("deep-tls.cipher:x", true, keys)).toBe("deeptls");
    expect(findingSource("dependency-manifest.vuln:lodash", true, keys)).toBe("dependencymanifest");
    expect(findingSource("api-spec.auth-bypass:/x", true, keys)).toBe("apispecinjection");
    expect(findingSource("mystery.thing", true, keys)).toBe("extended");
    expect(findingSource("nuclei.lookalike", false, keys)).toBe("base");
  });

  it("only lets a scan vouch for sources it ran", () => {
    expect(isCovered("base", PASSIVE)).toBe(true);
    expect(isCovered("nuclei", PASSIVE)).toBe(false);
    expect(isCovered("nuclei", FULL)).toBe(true);
    expect(isCovered("sqlmap", FULL)).toBe(false); // errored this time
    expect(isCovered("extended", FULL)).toBe(true);
    expect(isCovered("extended", PASSIVE)).toBe(false);
  });

  // Regression: base findings were "covered" even when their check errored,
  // so a TLS timeout or a rate-limited WPScan lookup marked them fixed.
  it("does not let a base check that errored or had no key vouch for its findings", () => {
    const coverage = scanCoverage(undefined, {
      target_url: "https://shop.example",
      findings: [],
      tls: { status: "error", note: "timeout" },
      wpVulnDb: { status: "error", note: "429" },
      hibp: { status: "not_configured", note: "no key" },
      domainRegistration: { status: "error" },
      headers: { status: "checked" },
      webapp: { status: "checked" },
    });
    expect(isCovered("base", coverage, "tls.expiring")).toBe(false);
    expect(isCovered("base", coverage, "wpvdb.plugin-vulnerability:elementor:123")).toBe(false);
    expect(isCovered("base", coverage, "hibp.breach:Adobe")).toBe(false);
    expect(isCovered("base", coverage, "domain.expiring")).toBe(false);
    expect(isCovered("base", coverage, "headers.csp-absent")).toBe(true);
    expect(isCovered("base", coverage, "webapp.missing-sri:script:https://cdn.x/a.js")).toBe(true);
    // Results stored before this was tracked: every base check counts as run.
    expect(isCovered("base", PASSIVE, "tls.expiring")).toBe(true);
  });

  it("keeps an open finding open when its check errored this scan", () => {
    const coverage = scanCoverage(undefined, { tls: { status: "error" } });
    expect(plan([existing({ check_id: "tls.expiring" })], [], coverage)).toEqual([]);
    expect(plan([existing({ check_id: "headers.csp-absent" })], [], coverage)).toEqual([
      expect.objectContaining({ check_id: "headers.csp-absent", resolved_at: SCAN_AT }),
    ]);
  });
});

describe("planLifecycleSync", () => {
  it("opens a new row for a first sighting", () => {
    const [row] = plan([], [f("tls.hsts-missing", { severity: "medium" })]);
    expect(row).toMatchObject({
      check_id: "tls.hsts-missing", severity: "medium", first_seen_at: SCAN_AT, last_seen_at: SCAN_AT,
      last_scan_id: "scan-now", resolved_at: null,
    });
  });

  it("uses the backfilled date for a site's first sync", () => {
    const [row] = plan([], [f("tls.hsts-missing")], PASSIVE, new Map([["tls.hsts-missing", daysBefore(12)]]));
    expect(row.first_seen_at).toBe(daysBefore(12));
  });

  it("keeps the clock running for a finding that's still there", () => {
    const [row] = plan([existing({ sla_warned_at: daysBefore(2) })], [f("headers.csp-absent", { title: "CSP still missing" })]);
    expect(row).toMatchObject({ first_seen_at: daysBefore(20), last_seen_at: SCAN_AT, title: "CSP still missing", sla_warned_at: daysBefore(2) });
  });

  it("clears alert markers when the severity changes", () => {
    const [row] = plan([existing({ sla_warned_at: daysBefore(2) })], [f("headers.csp-absent", { severity: "critical" })]);
    expect(row).toMatchObject({ severity: "critical", first_seen_at: daysBefore(20), sla_warned_at: null });
  });

  it("resolves a base finding the scan no longer reports", () => {
    const [row] = plan([existing()], []);
    expect(row).toMatchObject({ check_id: "headers.csp-absent", resolved_at: SCAN_AT, first_seen_at: daysBefore(20) });
  });

  // The whole point of `source`: a passive on-demand scan can't see what the
  // active tools found, so its silence mustn't close the SLA clock.
  it("never lets a passive scan resolve an active-tool finding", () => {
    expect(plan([existing({ check_id: "nuclei.finding:cve-x", source: "nuclei" })], [])).toEqual([]);
  });

  it("resolves an active-tool finding once that tool runs again without it", () => {
    const [row] = plan([existing({ check_id: "nuclei.finding:cve-x", source: "nuclei" })], [], FULL);
    expect(row.resolved_at).toBe(SCAN_AT);
  });

  it("doesn't resolve when the producing tool errored this time", () => {
    expect(plan([existing({ check_id: "sqlmap.sqli:id", source: "sqlmap" })], [], FULL)).toEqual([]);
  });

  it("reopens a recently resolved finding with its original first-seen date", () => {
    const [row] = plan([existing({ resolved_at: daysBefore(3), sla_warned_at: daysBefore(5) })], [f("headers.csp-absent")]);
    expect(row).toMatchObject({ resolved_at: null, first_seen_at: daysBefore(20), sla_warned_at: daysBefore(5) });
  });

  it("starts a fresh occurrence when it comes back long after being fixed", () => {
    const [row] = plan(
      [existing({ resolved_at: daysBefore(30), sla_warned_at: daysBefore(35), sla_breach_notified_at: daysBefore(32) })],
      [f("headers.csp-absent")]
    );
    expect(row).toMatchObject({ resolved_at: null, first_seen_at: SCAN_AT, sla_warned_at: null, sla_breach_notified_at: null });
  });

  it("leaves already-resolved rows alone", () => {
    expect(plan([existing({ resolved_at: daysBefore(3) })], [])).toEqual([]);
  });

  it("emits complete rows so an upsert can't null out columns", () => {
    const keys = Object.keys(plan([], [f("tls.x")])[0]).sort();
    expect(keys).toEqual(Object.keys(existing()).sort());
  });
});

describe("dedupeFindings", () => {
  it("keeps the most severe copy of a repeated checkId", () => {
    expect(dedupeFindings([f("a", { severity: "low" }), f("a", { severity: "critical" }), f("b")]).map((x) => [x.checkId, x.severity])).toEqual([
      ["a", "critical"],
      ["b", "high"],
    ]);
  });
});

describe("backfillFirstSeen", () => {
  const scan = (daysAgo: number, ids: string[], coverage = PASSIVE): HistoricalScan => ({
    createdAt: daysBefore(daysAgo),
    checkIds: new Set(ids),
    coverage,
  });

  it("walks back through consecutive sightings", () => {
    const history = [scan(1, ["a"]), scan(2, ["a"]), scan(3, []), scan(4, ["a"])];
    expect(backfillFirstSeen([f("a")], history, SCAN_AT).get("a")).toBe(daysBefore(2));
  });

  it("isn't interrupted by scans that couldn't have seen it", () => {
    const history = [scan(1, ["nuclei.x"], FULL), scan(2, []), scan(3, []), scan(4, ["nuclei.x"], FULL), scan(5, [], FULL)];
    expect(backfillFirstSeen([f("nuclei.x", { source: "nuclei" })], history, SCAN_AT).get("nuclei.x")).toBe(daysBefore(4));
  });

  it("dates a finding with no history to this scan", () => {
    expect(backfillFirstSeen([f("a")], [], SCAN_AT).get("a")).toBe(SCAN_AT);
  });
});

describe("syncFindingLifecycle", () => {
  function client(opts: { existing?: unknown[]; loadError?: { code: string; message: string }; history?: unknown[] }) {
    const upsert = vi.fn().mockResolvedValue({ error: null });
    const from = vi.fn((table: string) => {
      const builder: Record<string, unknown> = {};
      for (const m of ["select", "eq", "neq", "lt", "order"]) builder[m] = () => builder;
      if (table === "finding_lifecycle") {
        builder.eq = () => builder;
        builder.then = (resolve: (v: unknown) => unknown) =>
          Promise.resolve(opts.loadError ? { data: null, error: opts.loadError } : { data: opts.existing ?? [], error: null }).then(resolve);
        builder.upsert = upsert;
      } else {
        builder.limit = () => Promise.resolve({ data: opts.history ?? [] });
      }
      return builder;
    });
    return { client: { from } as never, upsert, from };
  }

  const input = {
    ownerId: "o1",
    scanId: "scan-now",
    targetUrl: "https://Shop.Example/path",
    scanAt: SCAN_AT,
    findings: [
      { severity: "high" as const, title: "CSP missing", detail: "d", checkId: "headers.csp-absent" },
      { severity: "low" as const, title: "untracked", detail: "d" },
    ],
    extendedCheckIds: new Set<string>(),
    extended: undefined,
  };

  it("does nothing, quietly, before migration 043", async () => {
    const { client: c, upsert } = client({ loadError: { code: "42P01", message: "relation does not exist" } });
    expect(await syncFindingLifecycle(c, input)).toBeNull();
    expect(upsert).not.toHaveBeenCalled();
  });

  it("backfills a site's first sync from its scan history", async () => {
    const { client: c, upsert } = client({
      existing: [],
      history: [
        { target_url: "https://shop.example", created_at: daysBefore(1), scan_results: [{ results: { findings: [{ checkId: "headers.csp-absent" }] } }] },
        { target_url: "https://other.example", created_at: daysBefore(2), scan_results: [{ results: { findings: [] } }] },
        { target_url: "https://shop.example/", created_at: daysBefore(3), scan_results: [{ results: { findings: [{ checkId: "headers.csp-absent" }] } }] },
      ],
    });
    expect(await syncFindingLifecycle(c, input)).toBe("shop.example");
    const [rows, options] = upsert.mock.calls[0];
    expect(options).toEqual({ onConflict: "owner,target_host,check_id" });
    expect(rows).toHaveLength(1); // the finding without a checkId isn't tracked
    expect(rows[0]).toMatchObject({ target_host: "shop.example", check_id: "headers.csp-absent", first_seen_at: daysBefore(3) });
  });

  it("skips the history walk once the site has rows", async () => {
    const { client: c, from } = client({ existing: [existing({ check_id: "headers.csp-absent" })] });
    await syncFindingLifecycle(c, input);
    expect(from).not.toHaveBeenCalledWith("scans");
  });
});

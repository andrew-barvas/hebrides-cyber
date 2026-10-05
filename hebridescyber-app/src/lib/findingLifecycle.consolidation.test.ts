import { describe, it, expect, vi } from "vitest";
import { planLifecycleSync, scanCoverage, syncFindingLifecycle, type CurrentFinding, type LifecycleDbRow } from "./findingLifecycle";

const SCAN_AT = "2026-09-27T09:00:00.000Z";
const daysBefore = (n: number) => new Date(Date.parse(SCAN_AT) - n * 86_400_000).toISOString();
const FULL = scanCoverage({ nuclei: { status: "completed" }, zap: { status: "completed" } });
const PASSIVE = scanCoverage(undefined);

function row(overrides: Partial<LifecycleDbRow> = {}): LifecycleDbRow {
  return {
    owner: "o1", target_host: "shop.example", check_id: "tls.hsts-missing", severity: "medium", title: "t", source: "base",
    first_seen_at: daysBefore(5), last_seen_at: daysBefore(1), last_scan_id: "prev", resolved_at: null,
    sla_warned_at: null, sla_breach_notified_at: null, ...overrides,
  };
}
const cur = (checkId: string, source = "base"): CurrentFinding => ({ checkId, severity: "medium", title: checkId, source });
const merged = new Map([["zap.alert:HSTS", "tls.hsts-missing"]]);

function plan(existing: LifecycleDbRow[], current: CurrentFinding[], opts: { merged?: Map<string, string>; coverage?: ReturnType<typeof scanCoverage>; backfill?: Map<string, string> } = {}) {
  return planLifecycleSync({
    owner: "o1", host: "shop.example", scanId: "now", scanAt: SCAN_AT, existing, current,
    coverage: opts.coverage ?? FULL, backfill: opts.backfill, merged: opts.merged,
  });
}

describe("planLifecycleSync with consolidated duplicates", () => {
  it("resolves an open duplicate row, even on a scan that could not have run its tool", () => {
    const dup = row({ check_id: "zap.alert:HSTS", source: "zap", first_seen_at: daysBefore(30) });
    const out = plan([row(), dup], [cur("tls.hsts-missing")], { merged, coverage: PASSIVE });
    expect(out.find((r) => r.check_id === "zap.alert:HSTS")?.resolved_at).toBe(SCAN_AT);
  });

  it("without the merge map, a passive scan leaves the same duplicate row alone", () => {
    const dup = row({ check_id: "zap.alert:HSTS", source: "zap" });
    const out = plan([row(), dup], [cur("tls.hsts-missing")], { coverage: PASSIVE });
    expect(out.find((r) => r.check_id === "zap.alert:HSTS")).toBeUndefined();
  });

  it("moves the canonical's SLA clock back to the earliest duplicate it absorbed", () => {
    const dup = row({ check_id: "zap.alert:HSTS", source: "zap", first_seen_at: daysBefore(30) });
    const out = plan([row({ first_seen_at: daysBefore(5) }), dup], [cur("tls.hsts-missing")], { merged });
    expect(out.find((r) => r.check_id === "tls.hsts-missing")?.first_seen_at).toBe(daysBefore(30));
  });

  it("never moves a canonical's first-seen later", () => {
    const dup = row({ check_id: "zap.alert:HSTS", source: "zap", first_seen_at: daysBefore(2) });
    const out = plan([row({ first_seen_at: daysBefore(5) }), dup], [cur("tls.hsts-missing")], { merged });
    expect(out.find((r) => r.check_id === "tls.hsts-missing")?.first_seen_at).toBe(daysBefore(5));
  });

  it("gives a brand-new canonical row the earliest duplicate's first-seen, keeping the earliest of several", () => {
    const m = new Map([["zap.alert:HSTS", "tls.hsts-missing"], ["nuclei.finding:hsts", "tls.hsts-missing"]]);
    const rows = [
      row({ check_id: "zap.alert:HSTS", source: "zap", first_seen_at: daysBefore(30) }),
      row({ check_id: "nuclei.finding:hsts", source: "nuclei", first_seen_at: daysBefore(40) }),
    ];
    const out = plan(rows, [cur("tls.hsts-missing")], { merged: m });
    expect(out.find((r) => r.check_id === "tls.hsts-missing")?.first_seen_at).toBe(daysBefore(40));
  });

  it("ignores an already-resolved duplicate row", () => {
    const dup = row({ check_id: "zap.alert:HSTS", source: "zap", first_seen_at: daysBefore(60), resolved_at: daysBefore(50) });
    const out = plan([dup], [cur("tls.hsts-missing")], { merged, backfill: new Map([["tls.hsts-missing", daysBefore(3)]]) });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ check_id: "tls.hsts-missing", first_seen_at: daysBefore(3) });
  });

  it("does not resolve a duplicate whose canonical is not in this scan", () => {
    const dup = row({ check_id: "zap.alert:HSTS", source: "zap" });
    const out = plan([dup], [], { merged, coverage: PASSIVE });
    expect(out).toEqual([]);
  });
});

describe("syncFindingLifecycle with consolidated duplicates", () => {
  it("derives the merge map from corroboratedBy and resolves the old duplicate row", async () => {
    const upsert = vi.fn().mockResolvedValue({ error: null });
    const existing = [row({ first_seen_at: daysBefore(2) }), row({ check_id: "zap.alert:HSTS", source: "zap", first_seen_at: daysBefore(9) })];
    const from = vi.fn(() => {
      const b: Record<string, unknown> = {};
      for (const m of ["select", "eq"]) b[m] = () => b;
      b.then = (resolve: (v: unknown) => unknown) => Promise.resolve({ data: existing, error: null }).then(resolve);
      b.upsert = upsert;
      return b;
    });
    const host = await syncFindingLifecycle({ from } as never, {
      ownerId: "o1", scanId: "now", targetUrl: "https://shop.example/", scanAt: SCAN_AT,
      findings: [
        { severity: "medium", title: "HSTS", detail: "d", checkId: "tls.hsts-missing", corroboratedBy: [{ tool: "ZAP", checkId: "zap.alert:HSTS", title: "z" }] },
        { severity: "low", title: "no id", detail: "d", corroboratedBy: [{ tool: "ZAP", checkId: "zap.alert:X", title: "z" }] },
      ],
      extendedCheckIds: new Set<string>(),
      extended: undefined,
    });
    expect(host).toBe("shop.example");
    const rows = upsert.mock.calls[0][0] as LifecycleDbRow[];
    expect(rows.find((r) => r.check_id === "zap.alert:HSTS")?.resolved_at).toBe(SCAN_AT);
    expect(rows.find((r) => r.check_id === "tls.hsts-missing")?.first_seen_at).toBe(daysBefore(9));
  });

  it("counts a folded duplicate as present in a historical scan when backfilling", async () => {
    const upsert = vi.fn().mockResolvedValue({ error: null });
    const from = vi.fn((table: string) => {
      const b: Record<string, unknown> = {};
      for (const m of ["select", "eq", "neq", "lt", "order"]) b[m] = () => b;
      if (table === "finding_lifecycle") {
        b.then = (resolve: (v: unknown) => unknown) => Promise.resolve({ data: [], error: null }).then(resolve);
        b.upsert = upsert;
      } else {
        b.limit = () =>
          Promise.resolve({
            data: [
              {
                target_url: "https://shop.example",
                created_at: daysBefore(4),
                scan_results: [{ results: { findings: [{ checkId: "headers.csp-absent", corroboratedBy: [{ tool: "ZAP", checkId: "zap.alert:CSP", title: "z" }] }] } }],
              },
            ],
          });
      }
      return b;
    });
    await syncFindingLifecycle({ from } as never, {
      ownerId: "o1", scanId: "now", targetUrl: "https://shop.example/", scanAt: SCAN_AT,
      findings: [{ severity: "medium", title: "CSP", detail: "d", checkId: "zap.alert:CSP" }],
      extendedCheckIds: new Set(["zap.alert:CSP"]),
      extended: { zap: { status: "completed" } },
    });
    const rows = upsert.mock.calls[0][0] as LifecycleDbRow[];
    expect(rows[0]).toMatchObject({ check_id: "zap.alert:CSP", first_seen_at: daysBefore(4) });
  });
});

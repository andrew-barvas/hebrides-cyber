import { afterEach, describe, expect, it, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  MAX_MONITORS_PER_REQUEST,
  createMonitorsForTargets,
  decideUptimeAlert,
  planSync,
  syncAllOwners,
  syncOwnerMonitors,
  type StoredUptimeMonitor,
} from "./uptimeService";
import type { ProviderResult, UptimeMonitor, UptimeProvider } from "./uptimeProvider";

type Row = Record<string, unknown>;

/** Minimal chainable Supabase fake: eq/is filters, select/insert/update/delete over in-memory tables. */
function fakeDb(tables: Record<string, Row[]>, opts: { failInsert?: boolean; failSelect?: string } = {}) {
  const ops: Array<{ table: string; op: string; payload?: unknown; filters?: Array<[string, unknown]> }> = [];
  const db = {
    from(table: string) {
      const filters: Array<[string, unknown]> = [];
      let mode: "select" | "update" | "delete" = "select";
      let patch: Row = {};
      let returning = false;
      const matching = () => (tables[table] ?? []).filter((r) => filters.every(([c, v]) => (r[c] ?? null) === v));
      const exec = () => {
        if (mode === "update") {
          const hit = matching();
          hit.forEach((r) => Object.assign(r, patch));
          ops.push({ table, op: "update", payload: patch, filters: [...filters] });
          return { data: returning ? hit.map((r) => ({ id: r.id })) : null, error: null };
        }
        if (mode === "delete") {
          tables[table] = (tables[table] ?? []).filter((r) => !matching().includes(r));
          return { data: null, error: null };
        }
        if (opts.failSelect === table) return { data: null, error: { message: `${table} read failed` } };
        // Copies, like a real read: a later write must not change what an earlier read saw.
        return { data: matching().map((r) => ({ ...r })), error: null };
      };
      const b: Record<string, unknown> = {
        select: () => ((returning = mode === "update"), b),
        order: () => b,
        eq: (c: string, v: unknown) => (filters.push([c, v]), b),
        is: (c: string, v: unknown) => (filters.push([c, v]), b),
        update: (p: Row) => ((mode = "update"), (patch = p), b),
        delete: () => ((mode = "delete"), b),
        insert: (row: Row) => {
          ops.push({ table, op: "insert", payload: row });
          if (opts.failInsert) return Promise.resolve({ error: { message: "insert failed" } });
          (tables[table] ??= []).push({ id: `new-${(tables[table] ?? []).length}`, ...row });
          return Promise.resolve({ error: null });
        },
        maybeSingle: () => Promise.resolve({ data: matching()[0] ?? null, error: null }),
        then: (resolve: (v: unknown) => unknown) => Promise.resolve(exec()).then(resolve),
      };
      return b;
    },
  };
  return { db: db as unknown as SupabaseClient, ops, tables };
}

const NOW = new Date("2026-10-23T12:00:00Z");

function monitor(over: Partial<UptimeMonitor> = {}): UptimeMonitor {
  return { externalId: "1", name: "m", url: "https://shop.example.co.uk", status: "up", stateDurationSeconds: 100, ...over };
}

function provider(over: Partial<UptimeProvider> = {}): UptimeProvider & { listMonitors: ReturnType<typeof vi.fn>; createMonitor: ReturnType<typeof vi.fn> } {
  return {
    id: "uptimerobot",
    validate: vi.fn(async () => ({ ok: true, value: true }) as ProviderResult<true>),
    listMonitors: vi.fn(async () => ({ ok: true, value: [] }) as ProviderResult<UptimeMonitor[]>),
    createMonitor: vi.fn(async () => ({ ok: true, value: monitor({ externalId: "99", status: "unknown" }) }) as ProviderResult<UptimeMonitor>),
    ...over,
  } as never;
}

describe("decideUptimeAlert", () => {
  it.each([
    [false, "down", "down"],
    [true, "down", null],
    [true, "up", "recovered"],
    [false, "up", null],
    [false, "seems_down", null],
    [true, "seems_down", null],
    [true, "paused", null],
    [true, "unknown", null],
    [false, "unknown", null],
  ] as const)("alerted=%s next=%s -> %s", (alerted, next, expected) => {
    expect(decideUptimeAlert(alerted, next)).toBe(expected);
  });

  it("gives exactly one down and one recovered across a flapping outage", () => {
    let alerted = false;
    const fired: string[] = [];
    for (const s of ["up", "seems_down", "down", "down", "seems_down", "down", "up", "up"] as const) {
      const a = decideUptimeAlert(alerted, s);
      if (a) fired.push(a);
      if (a === "down") alerted = true;
      if (a === "recovered") alerted = false;
    }
    expect(fired).toEqual(["down", "recovered"]);
  });
});

describe("planSync", () => {
  const row = (over: Partial<StoredUptimeMonitor> = {}): StoredUptimeMonitor => ({
    id: "r1",
    target_url: "https://shop.example.co.uk",
    external_id: "1",
    last_status: "up",
    last_status_at: "2026-10-23T10:00:00Z",
    down_alerted_at: null,
    ...over,
  });

  it("opens an outage on down and remembers it", () => {
    const plan = planSync([row()], [monitor({ status: "down" })], NOW);
    expect(plan.alerts).toEqual([{ kind: "down", targetUrl: "https://shop.example.co.uk", monitorId: "r1", previousDownAlertedAt: null }]);
    expect(plan.updates[0]).toMatchObject({ last_status: "down", last_status_at: NOW.toISOString(), down_alerted_at: NOW.toISOString() });
  });

  it("does not repeat the down alert while it stays down, and keeps the original down time", () => {
    const plan = planSync([row({ last_status: "down", last_status_at: "2026-10-23T11:00:00Z", down_alerted_at: "2026-10-23T11:00:00Z" })], [monitor({ status: "down" })], NOW);
    expect(plan.alerts).toEqual([]);
    expect(plan.updates[0]).toMatchObject({ last_status_at: "2026-10-23T11:00:00Z", down_alerted_at: "2026-10-23T11:00:00Z" });
  });

  it("closes the outage on up", () => {
    const plan = planSync([row({ last_status: "down", down_alerted_at: "2026-10-23T11:00:00Z" })], [monitor({ status: "up" })], NOW);
    expect(plan.alerts).toEqual([{ kind: "recovered", targetUrl: "https://shop.example.co.uk", monitorId: "r1", previousDownAlertedAt: "2026-10-23T11:00:00Z" }]);
    expect(plan.updates[0].down_alerted_at).toBeNull();
  });

  it("reports a monitor deleted at the provider as missing and leaves it untouched", () => {
    const plan = planSync([row({ external_id: "gone" })], [monitor()], NOW);
    expect(plan.missing).toEqual(["https://shop.example.co.uk"]);
    expect(plan.updates).toEqual([]);
    expect(plan.alerts).toEqual([]);
  });

  it("stores an unknown status without alerting", () => {
    const plan = planSync([row()], [monitor({ status: "unknown" })], NOW);
    expect(plan.alerts).toEqual([]);
    expect(plan.updates[0].last_status).toBe("unknown");
  });
});

describe("syncOwnerMonitors", () => {
  const stored = () => ({
    uptime_monitors: [{ id: "r1", owner: "o1", provider: "uptimerobot", target_url: "https://shop.example.co.uk", external_id: "1", last_status: "up", last_status_at: null, down_alerted_at: null }],
    uptime_integrations: [{ id: "i1", owner: "o1", last_sync_at: null, last_error: null }],
  });

  it("updates rows, returns alerts and records the sync time", async () => {
    const { db, tables } = fakeDb(stored());
    const p = provider({ listMonitors: vi.fn(async () => ({ ok: true, value: [monitor({ status: "down" })] })) } as never);
    const r = await syncOwnerMonitors(db, "o1", "i1", p, NOW);
    expect(r).toMatchObject({ ok: true, updated: 1, alerts: [{ kind: "down" }] });
    expect(tables.uptime_monitors[0]).toMatchObject({ last_status: "down" });
    expect(tables.uptime_integrations[0]).toMatchObject({ last_sync_at: NOW.toISOString(), last_error: null });
  });

  it("announces an outage once when the cron and a dashboard refresh sync at the same moment", async () => {
    const { db, tables } = fakeDb(stored());
    const p = provider({ listMonitors: vi.fn(async () => ({ ok: true, value: [monitor({ status: "down" })] })) } as never);
    const [a, b] = await Promise.all([syncOwnerMonitors(db, "o1", "i1", p, NOW), syncOwnerMonitors(db, "o1", "i1", p, NOW)]);
    const alerts = [a, b].flatMap((r) => (r.ok ? r.alerts : []));
    expect(alerts).toEqual([expect.objectContaining({ kind: "down", targetUrl: "https://shop.example.co.uk" })]);
    expect(tables.uptime_monitors[0].down_alerted_at).toBe(NOW.toISOString());
  });

  it("announces recovery once, and only for the outage it read", async () => {
    const t = stored();
    Object.assign(t.uptime_monitors[0], { last_status: "down", down_alerted_at: "2026-10-23T11:00:00Z" });
    const { db, tables } = fakeDb(t);
    const p = provider({ listMonitors: vi.fn(async () => ({ ok: true, value: [monitor({ status: "up" })] })) } as never);
    const [a, b] = await Promise.all([syncOwnerMonitors(db, "o1", "i1", p, NOW), syncOwnerMonitors(db, "o1", "i1", p, NOW)]);
    expect([a, b].flatMap((r) => (r.ok ? r.alerts.map((x) => x.kind) : []))).toEqual(["recovered"]);
    expect(tables.uptime_monitors[0].down_alerted_at).toBeNull();
  });

  it("on a provider failure records last_error and changes no status", async () => {
    const { db, tables } = fakeDb(stored());
    const p = provider({ listMonitors: vi.fn(async () => ({ ok: false, kind: "rate_limited", error: "slow down", retryAfterSeconds: 30 })) } as never);
    const r = await syncOwnerMonitors(db, "o1", "i1", p, NOW);
    expect(r).toMatchObject({ ok: false, kind: "rate_limited", retryAfterSeconds: 30 });
    expect(tables.uptime_monitors[0].last_status).toBe("up");
    expect(tables.uptime_integrations[0].last_error).toBe("slow down");
  });
});

describe("createMonitorsForTargets", () => {
  const base = () => ({
    users: [{ id: "o1", is_admin: false }],
    verifications: [{ owner: "o1", domain: "shop.example.co.uk", verified_at: "2026-01-01" }],
    monitored_targets: [
      { owner: "o1", target_url: "https://shop.example.co.uk" },
      { owner: "o1", target_url: "https://blog.example.co.uk" },
    ],
    uptime_monitors: [] as Row[],
  });

  it("creates a monitor for a verified, monitored target and records it", async () => {
    const { db, tables } = fakeDb(base());
    const p = provider();
    const r = await createMonitorsForTargets(db, "o1", p, ["https://Shop.example.co.uk/"]);
    expect(r).toEqual([{ targetUrl: "https://shop.example.co.uk", result: "created" }]);
    expect(p.createMonitor).toHaveBeenCalledWith({ url: "https://shop.example.co.uk", name: "Hebrides: shop.example.co.uk" });
    expect(tables.uptime_monitors[0]).toMatchObject({ owner: "o1", provider: "uptimerobot", external_id: "99" });
  });

  it("adopts a monitor that already exists in their account instead of creating a duplicate", async () => {
    const { db } = fakeDb(base());
    const p = provider({ listMonitors: vi.fn(async () => ({ ok: true, value: [monitor({ externalId: "7", url: "https://shop.example.co.uk/" })] })) } as never);
    const r = await createMonitorsForTargets(db, "o1", p, ["https://shop.example.co.uk"]);
    expect(r[0].result).toBe("adopted");
    expect(p.createMonitor).not.toHaveBeenCalled();
  });

  it("skips targets that already have a monitor", async () => {
    const t = base();
    t.uptime_monitors.push({ owner: "o1", provider: "uptimerobot", target_url: "https://shop.example.co.uk", external_id: "1" });
    const { db } = fakeDb(t);
    const p = provider();
    expect((await createMonitorsForTargets(db, "o1", p, ["https://shop.example.co.uk"]))[0].result).toBe("exists");
    expect(p.listMonitors).not.toHaveBeenCalled();
  });

  it("refuses a target they do not monitor, or have not verified, or that is not a URL, without calling the provider", async () => {
    const t = base();
    t.verifications = [];
    const { db } = fakeDb(t);
    const p = provider();
    const r = await createMonitorsForTargets(db, "o1", p, ["https://other.example", "https://blog.example.co.uk", "javascript:alert(1)"]);
    expect(r.map((x) => x.result)).toEqual(["not_monitored", "not_verified", "invalid_url"]);
    expect(p.listMonitors).not.toHaveBeenCalled();
    expect(p.createMonitor).not.toHaveBeenCalled();
  });

  it("lets an admin monitor an unverified target", async () => {
    const t = base();
    t.users = [{ id: "o1", is_admin: true }];
    t.verifications = [];
    const { db } = fakeDb(t);
    expect((await createMonitorsForTargets(db, "o1", provider(), ["https://shop.example.co.uk"]))[0].result).toBe("created");
  });

  it("stops at a rate limit and marks the rest skipped", async () => {
    const t = base();
    t.verifications.push({ owner: "o1", domain: "blog.example.co.uk", verified_at: "2026-01-01" });
    const { db } = fakeDb(t);
    const p = provider({ createMonitor: vi.fn(async () => ({ ok: false, kind: "rate_limited", error: "429" })) } as never);
    const r = await createMonitorsForTargets(db, "o1", p, ["https://shop.example.co.uk", "https://blog.example.co.uk"]);
    expect(r.map((x) => x.result)).toEqual(["error", "skipped"]);
    expect(p.createMonitor).toHaveBeenCalledTimes(1);
  });

  it("reports a failed listing as an error and writes nothing", async () => {
    const { db, tables } = fakeDb(base());
    const p = provider({ listMonitors: vi.fn(async () => ({ ok: false, kind: "auth", error: "bad key" })) } as never);
    const r = await createMonitorsForTargets(db, "o1", p, ["https://shop.example.co.uk"]);
    expect(r[0]).toMatchObject({ result: "error", kind: "auth" });
    expect(tables.uptime_monitors).toHaveLength(0);
  });

  it("reports a failed read of their sites as an error, not 'not one of your sites'", async () => {
    const { db, tables } = fakeDb(base(), { failSelect: "monitored_targets" });
    const p = provider();
    const r = await createMonitorsForTargets(db, "o1", p, ["https://shop.example.co.uk", "https://blog.example.co.uk"]);
    expect(r.map((x) => x.result)).toEqual(["error", "error"]);
    expect(r[0]).toMatchObject({ kind: "database", error: "monitored_targets read failed" });
    expect(p.listMonitors).not.toHaveBeenCalled();
    expect(tables.uptime_monitors).toHaveLength(0);
  });

  it("surfaces a database failure instead of claiming success", async () => {
    const { db } = fakeDb(base(), { failInsert: true });
    const r = await createMonitorsForTargets(db, "o1", provider(), ["https://shop.example.co.uk"]);
    expect(r[0]).toMatchObject({ result: "error", kind: "database" });
  });

  it("only acts on the first batch and skips the rest", async () => {
    const { db } = fakeDb(base());
    const urls = Array.from({ length: MAX_MONITORS_PER_REQUEST + 2 }, (_, i) => `https://s${i}.example`);
    const r = await createMonitorsForTargets(db, "o1", provider(), urls);
    expect(r).toHaveLength(MAX_MONITORS_PER_REQUEST + 2);
    expect(r.slice(MAX_MONITORS_PER_REQUEST).every((x) => x.result === "skipped")).toBe(true);
  });
});

describe("syncAllOwners", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const tables = () => ({
    uptime_integrations: [
      { id: "i1", owner: "o1", provider: "uptimerobot", api_key: "key-o1", last_sync_at: null, last_error: null },
      { id: "i2", owner: "o2", provider: "uptimerobot", api_key: "key-o2", last_sync_at: null, last_error: null },
      { id: "i3", owner: "o3", provider: "uptimerobot", api_key: "key-o3", last_sync_at: null, last_error: null },
    ],
    uptime_monitors: [
      { id: "r1", owner: "o1", provider: "uptimerobot", target_url: "https://shop.example.co.uk", external_id: "1", last_status: "up", last_status_at: null, down_alerted_at: null },
      { id: "r2", owner: "o2", provider: "uptimerobot", target_url: "https://lapsed.example.co.uk", external_id: "2", last_status: "up", last_status_at: null, down_alerted_at: null },
    ] as Row[],
  });

  function stubUptimeRobot() {
    const keys: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init: RequestInit) => {
        keys.push(String((init.headers as Record<string, string>).Authorization));
        return new Response(JSON.stringify({ data: [{ id: 1, friendlyName: "m", url: "https://shop.example.co.uk", status: "DOWN" }] }), { status: 200 });
      }),
    );
    return keys;
  }

  it("syncs Pro owners, skips lapsed ones without touching their key, and counts plan-check failures", async () => {
    const keys = stubUptimeRobot();
    const { db, tables: t } = fakeDb(tables());
    const sendAlert = vi.fn(async () => {});
    const gate = vi.fn(async (_db: SupabaseClient, owner: string) => (owner === "o1" ? "ok" : owner === "o2" ? "denied" : "error") as "ok" | "denied" | "error");
    const r = await syncAllOwners(db, { gate, sendAlert });
    expect(r).toEqual({ ok: true, summary: { synced: 1, failed: 1, lapsed: 1, alerts: 1 } });
    expect(sendAlert).toHaveBeenCalledWith(db, "o1", "down", "https://shop.example.co.uk");
    expect(keys).toEqual(["Bearer key-o1"]);
    // The lapsed owner's stored status is left exactly as it was.
    expect(t.uptime_monitors[1]).toMatchObject({ last_status: "up", down_alerted_at: null });
  });

  it("reports a failure to list connections instead of a clean run", async () => {
    const { db } = fakeDb(tables(), { failSelect: "uptime_integrations" });
    const r = await syncAllOwners(db, { gate: vi.fn(), sendAlert: vi.fn() });
    expect(r).toEqual({ ok: false, error: "uptime_integrations read failed" });
  });
});

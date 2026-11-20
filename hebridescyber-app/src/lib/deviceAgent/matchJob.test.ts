import { describe, it, expect, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { needsMatch, runDeviceMatchJob } from "./matchJob";
import type { MatchDeps } from "./matching";
import { windowsInventory } from "./testFixtures";

const NOW = new Date("2026-11-20T09:00:00Z");

type Result = { data: unknown; error: { code?: string; message: string } | null };

function fakeDb(opts: { devices: Result; inventories: Record<string, Result>; updateError?: Result["error"] }) {
  const updates: Array<{ values: Record<string, unknown>; filters: Array<[string, unknown]> }> = [];
  const db = {
    from(table: string) {
      const filters: Array<[string, unknown]> = [];
      let values: Record<string, unknown> | null = null;
      const b: Record<string, unknown> = {
        select: () => b,
        is: () => b,
        not: () => b,
        order: () => b,
        eq: (col: string, val: unknown) => {
          filters.push([col, val]);
          if (values) {
            // the update chain resolves after its last eq
            if (filters.length === 2) {
              updates.push({ values, filters: [...filters] });
              return Promise.resolve({ error: opts.updateError ?? null });
            }
          }
          return b;
        },
        update: (v: Record<string, unknown>) => {
          values = v;
          return b;
        },
        limit: () => (table === "agent_devices" ? Promise.resolve(opts.devices) : b),
        maybeSingle: () => {
          const id = filters.find(([c]) => c === "device_id")?.[1] as string;
          return Promise.resolve(opts.inventories[id] ?? { data: null, error: null });
        },
      };
      return b;
    },
  } as unknown as SupabaseClient;
  return { db, updates };
}

function deps(): MatchDeps {
  return {
    cveIndex: null,
    queryOsvBatch: async () => ({ ok: true, vulnIds: [] }),
    fetchOsvVulnDetails: async () => ({ details: new Map(), failed: [] }),
    fetchEolProduct: async () => [{ cycle: "11-23h2-w", eol: "2027-11-10" }],
    now: NOW,
  };
}

const device = (id: string, last_seen_at: string, matched_at: string | null) => ({ id, owner: "o1", last_seen_at, matched_at, pending_first_seen: { "windows-update:KB5036893": "2026-11-12" } });

describe("needsMatch", () => {
  it("is true for never-matched devices and reports newer than the match", () => {
    expect(needsMatch({ last_seen_at: "2026-11-20T08:00:00Z", matched_at: null })).toBe(true);
    expect(needsMatch({ last_seen_at: "2026-11-20T08:00:00Z", matched_at: "2026-11-20T07:00:00Z" })).toBe(true);
    expect(needsMatch({ last_seen_at: "2026-11-20T08:00:00Z", matched_at: "2026-11-20T08:30:00Z" })).toBe(false);
  });
});

describe("runDeviceMatchJob", () => {
  it("is unavailable before migration 086", async () => {
    const { db } = fakeDb({ devices: { data: null, error: { code: "42P01", message: "relation does not exist" } }, inventories: {} });
    expect(await runDeviceMatchJob(db, async () => deps())).toEqual({ status: "unavailable" });
  });

  it("throws on any other read error", async () => {
    const { db } = fakeDb({ devices: { data: null, error: { code: "XX000", message: "boom" } }, inventories: {} });
    await expect(runDeviceMatchJob(db, async () => deps())).rejects.toThrow(/boom/);
  });

  it("doesn't open the matchers when nothing needs matching", async () => {
    const makeDeps = vi.fn(async () => deps());
    const { db } = fakeDb({ devices: { data: [device("d1", "2026-11-20T08:00:00Z", "2026-11-20T08:30:00Z")], error: null }, inventories: {} });
    expect(await runDeviceMatchJob(db, makeDeps)).toEqual({ status: "done", matched: 0, skipped: 0, errors: [] });
    expect(makeDeps).not.toHaveBeenCalled();
  });

  it("matches the latest report, re-evaluates and stores both, guarded on last_seen_at", async () => {
    const { db, updates } = fakeDb({
      devices: { data: [device("d1", "2026-11-20T08:00:00Z", null)], error: null },
      inventories: { d1: { data: { inventory: windowsInventory(), received_at: "2026-11-20T08:00:00Z" }, error: null } },
    });
    const res = await runDeviceMatchJob(db, async () => deps());
    expect(res).toEqual({ status: "done", matched: 1, skipped: 0, errors: [] });
    expect(updates).toHaveLength(1);
    const { values, filters } = updates[0];
    expect(filters).toEqual([["id", "d1"], ["last_seen_at", "2026-11-20T08:00:00Z"]]);
    expect(values.matched_at).toBe(NOW.toISOString());
    expect(values.patch_status).toBe("at_risk");
    expect((values.last_match as { osEol: unknown }).osEol).toMatchObject({ cycle: "11-23h2-w", state: "supported" });
    expect(values.evaluation).not.toHaveProperty("pendingFirstSeen");
  });

  it("skips devices whose stored report no longer validates, and writes nothing in a dry run", async () => {
    const { db, updates } = fakeDb({
      devices: { data: [device("bad", "2026-11-20T08:00:00Z", null), device("d2", "2026-11-20T08:00:00Z", null), device("none", "2026-11-20T08:00:00Z", null)], error: null },
      inventories: {
        bad: { data: { inventory: { schema_version: 99 }, received_at: "x" }, error: null },
        d2: { data: { inventory: windowsInventory(), received_at: "x" }, error: null },
      },
    });
    const res = await runDeviceMatchJob(db, async () => deps(), { dryRun: true });
    expect(res).toEqual({ status: "done", matched: 1, skipped: 2, errors: [] });
    expect(updates).toEqual([]);
  });

  it("collects per-device errors and carries on", async () => {
    const { db } = fakeDb({
      devices: { data: [device("d1", "2026-11-20T08:00:00Z", null), device("d2", "2026-11-20T08:00:00Z", null)], error: null },
      inventories: {
        d1: { data: null, error: { message: "read failed" } },
        d2: { data: { inventory: windowsInventory(), received_at: "x" }, error: null },
      },
      updateError: { message: "write failed" },
    });
    const res = await runDeviceMatchJob(db, async () => deps(), { limit: 5 });
    expect(res).toEqual({ status: "done", matched: 0, skipped: 0, errors: ["device d1: read failed", "device d2: write failed"] });
  });
});

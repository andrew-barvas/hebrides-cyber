import { describe, it, expect } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { clientParam, resolveClientScope } from "./clientScope";

type Result = { data: unknown; error: { code?: string; message: string } | null };

function fakeDb(clients: Result, targets: Result) {
  const calls: string[] = [];
  const db = {
    from: (table: string) => {
      const b: Record<string, unknown> = {};
      const result = () => (table === "clients" ? clients : targets);
      b.select = () => b;
      b.eq = (c: string, v: unknown) => (calls.push(`${table}.eq:${c}=${v}`), b);
      b.is = (c: string, v: unknown) => (calls.push(`${table}.is:${c}=${v}`), b);
      b.maybeSingle = () => Promise.resolve(result());
      b.then = (resolve: (r: Result) => unknown) => resolve(result());
      return b;
    },
  } as unknown as SupabaseClient;
  return { db, calls };
}

describe("clientParam", () => {
  it("returns the trimmed first value, or null when absent or blank", () => {
    expect(clientParam(" c1 ")).toBe("c1");
    expect(clientParam(["a", "b"])).toBe("a");
    expect(clientParam("   ")).toBeNull();
    expect(clientParam(undefined)).toBeNull();
    expect(clientParam([])).toBeNull();
  });
});

describe("resolveClientScope", () => {
  const sites: Result = { data: [{ target_url: "https://A.test/" }, { target_url: "https://a.test" }, { target_url: "not a url" }], error: null };

  it("resolves an owned client to its distinct, lower-cased hostnames", async () => {
    const { db, calls } = fakeDb({ data: { id: "c1" }, error: null }, sites);
    const r = await resolveClientScope(db, "o1", "c1");
    expect(r).toMatchObject({ ok: true, urls: ["https://A.test/", "https://a.test", "not a url"] });
    expect(r.ok && [...r.hosts]).toEqual(["a.test"]);
    expect(calls).toEqual(["clients.eq:id=c1", "clients.eq:owner=o1", "monitored_targets.eq:owner=o1", "monitored_targets.eq:client_id=c1"]);
  });

  it("404s for a client the owner does not have", async () => {
    const { db } = fakeDb({ data: null, error: null }, sites);
    expect(await resolveClientScope(db, "o1", "other")).toEqual({ ok: false, status: 404, error: "Client not found" });
  });

  it("resolves 'unassigned' without a client lookup", async () => {
    const { db, calls } = fakeDb({ data: null, error: { message: "should not be read" } }, sites);
    const r = await resolveClientScope(db, "o1", "unassigned");
    expect(r.ok).toBe(true);
    expect(calls).toEqual(["monitored_targets.eq:owner=o1", "monitored_targets.is:client_id=null"]);
  });

  it("503s when migration 063 is missing, 500s on other errors (client lookup)", async () => {
    expect(await resolveClientScope(fakeDb({ data: null, error: { code: "42P01", message: "x" } }, sites).db, "o1", "c1")).toMatchObject({ ok: false, status: 503 });
    expect(await resolveClientScope(fakeDb({ data: null, error: { message: "boom" } }, sites).db, "o1", "c1")).toMatchObject({ ok: false, status: 500 });
  });

  it("503s / 500s on the same errors when reading the sites", async () => {
    const ok: Result = { data: { id: "c1" }, error: null };
    expect(await resolveClientScope(fakeDb(ok, { data: null, error: { code: "42703", message: "x" } }).db, "o1", "c1")).toMatchObject({ ok: false, status: 503 });
    expect(await resolveClientScope(fakeDb(ok, { data: null, error: { message: "boom" } }).db, "o1", "c1")).toMatchObject({ ok: false, status: 500 });
  });

  it("tolerates a null site list", async () => {
    const r = await resolveClientScope(fakeDb({ data: { id: "c1" }, error: null }, { data: null, error: null }).db, "o1", "c1");
    expect(r).toMatchObject({ ok: true, urls: [] });
  });
});

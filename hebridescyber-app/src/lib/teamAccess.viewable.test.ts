import { describe, expect, it } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { callerCanView, listViewableAccounts } from "./teamAccess";

const ME = "me";
function client(tables: Record<string, unknown[]>): SupabaseClient {
  return {
    from: (t: string) => {
      const q = { select: () => q, eq: () => q, in: () => q, then: (r: (v: unknown) => void) => r({ data: tables[t] ?? [], error: null }) };
      return q;
    },
  } as unknown as SupabaseClient;
}

const db = client({
  team_members: [{ team_id: "t1", role: "member" }, { team_id: "t2", role: "developer" }, { team_id: "mine", role: "admin" }],
  teams: [{ id: "t1", owner_id: "zed" }, { id: "t2", owner_id: "amy" }, { id: "mine", owner_id: ME }],
  users: [{ id: "zed", email: "zed@example.com" }, { id: "amy", email: "amy@example.com" }],
});

describe("listViewableAccounts", () => {
  it("lists the owner of every team the caller is on, by email, never the caller's own", async () => {
    expect(await listViewableAccounts(db, ME)).toEqual([
      { ownerId: "amy", email: "amy@example.com", role: "developer" },
      { ownerId: "zed", email: "zed@example.com", role: "member" },
    ]);
  });

  it("is empty for someone on no team", async () => {
    expect(await listViewableAccounts(client({}), ME)).toEqual([]);
  });
});

describe("callerCanView", () => {
  it("allows the caller's own account and their teams' owners only", async () => {
    expect(await callerCanView(db, ME, ME)).toBe(true);
    expect(await callerCanView(db, ME, "zed")).toBe(true);
    expect(await callerCanView(db, ME, "stranger")).toBe(false);
  });
});

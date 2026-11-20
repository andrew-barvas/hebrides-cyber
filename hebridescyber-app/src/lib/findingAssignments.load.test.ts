import { describe, it, expect } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { loadAssignees, loadAssignments } from "./findingAssignments";

type R = { data: unknown; error: unknown };
function client(tables: Record<string, R | (() => never)>) {
  return {
    from: (t: string) => {
      const entry = tables[t];
      if (typeof entry === "function") entry();
      const r = (entry ?? { data: [], error: null }) as R;
      const q: Record<string, unknown> = {
        select: () => q, eq: () => q, in: () => q,
        maybeSingle: async () => r,
        then: (res: (v: unknown) => void) => res(r),
      };
      return q;
    },
  } as unknown as SupabaseClient;
}

const MISSING = { code: "42P01", message: 'relation "x" does not exist' };

describe("loadAssignees", () => {
  it("lists the owner first, then members by email, skipping the owner if listed as a member", async () => {
    const out = await loadAssignees(
      client({
        teams: { data: { id: "t" }, error: null },
        team_members: { data: [{ user_id: "zed", role: "member" }, { user_id: "owner", role: "admin" }, { user_id: "amy", role: "developer" }], error: null },
        users: { data: [{ id: "owner", email: "o@x.test" }, { id: "amy", email: "amy@x.test" }, { id: "zed", email: null }], error: null },
      }),
      "owner"
    );
    expect(out).toEqual({
      ok: true,
      assignees: [
        { id: "owner", email: "o@x.test", role: "owner" },
        { id: "zed", email: null, role: "member" },
        { id: "amy", email: "amy@x.test", role: "developer" },
      ],
    });
  });

  it("works for an owner with no team, or before the teams tables exist", async () => {
    const users = { data: [{ id: "owner", email: "o@x.test" }], error: null };
    expect(await loadAssignees(client({ teams: { data: null, error: null }, users }), "owner")).toEqual({ ok: true, assignees: [{ id: "owner", email: "o@x.test", role: "owner" }] });
    expect((await loadAssignees(client({ teams: { data: null, error: MISSING }, users }), "owner")).ok).toBe(true);
  });

  it("fails rather than guessing when a read fails or throws", async () => {
    expect(await loadAssignees(client({ teams: { data: null, error: { message: "boom" } } }), "o")).toEqual({ ok: false });
    expect(await loadAssignees(client({ teams: { data: { id: "t" }, error: null }, team_members: { data: null, error: { message: "boom" } } }), "o")).toEqual({ ok: false });
    expect(await loadAssignees(client({ teams: { data: null, error: null }, users: { data: null, error: { message: "boom" } } }), "o")).toEqual({ ok: false });
    expect(await loadAssignees(client({ teams: () => { throw new Error("network"); } }), "o")).toEqual({ ok: false });
  });
});

describe("loadAssignments", () => {
  it("returns the rows, says unavailable before migration 078, and flags other errors", async () => {
    const rows = [{ target_host: "a", check_id: "c", assignee: "u", assigned_at: "t" }];
    expect(await loadAssignments(client({ finding_assignments: { data: rows, error: null } }), "o")).toEqual({ available: true, rows, error: false });
    expect(await loadAssignments(client({ finding_assignments: { data: null, error: MISSING } }), "o")).toEqual({ available: false, rows: [], error: false });
    expect(await loadAssignments(client({ finding_assignments: { data: null, error: { message: "boom" } } }), "o")).toEqual({ available: true, rows: [], error: true });
    expect(await loadAssignments(client({ finding_assignments: () => { throw new Error("network"); } }), "o")).toEqual({ available: true, rows: [], error: true });
  });
});

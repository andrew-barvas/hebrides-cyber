import { describe, it, expect } from "vitest";
import { callerCanActFor } from "./teamAccess";

const OWNER_ID = "owner-1";
const CALLER_ID = "caller-1";
const TEAM_ID = "team-1";

type QueueMap = Record<string, unknown[]>;

function fakeSupabase(queues: QueueMap) {
  return {
    from: (table: string) => {
      const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
      const builder: Record<string, unknown> = {
        select: () => builder,
        eq: () => builder,
        maybeSingle: next,
      };
      return builder;
    },
    // Cast away the rest of SupabaseClient's surface — callerCanActFor only
    // ever calls .from(...).select(...).eq(...).eq(...).maybeSingle().
  } as unknown as Parameters<typeof callerCanActFor>[0];
}

describe("callerCanActFor", () => {
  it("returns true when the caller IS the target owner, without any lookup", async () => {
    const supabase = fakeSupabase({});
    expect(await callerCanActFor(supabase, OWNER_ID, OWNER_ID)).toBe(true);
  });

  it("returns false when the owner has no team at all", async () => {
    const supabase = fakeSupabase({ teams: [{ data: null, error: null }] });
    expect(await callerCanActFor(supabase, CALLER_ID, OWNER_ID)).toBe(false);
  });

  it("returns false when the caller isn't a member of the owner's team", async () => {
    const supabase = fakeSupabase({
      teams: [{ data: { id: TEAM_ID }, error: null }],
      team_members: [{ data: null, error: null }],
    });
    expect(await callerCanActFor(supabase, CALLER_ID, OWNER_ID)).toBe(false);
  });

  it.each(["admin", "developer"])("returns true for a team '%s' member", async (role) => {
    const supabase = fakeSupabase({
      teams: [{ data: { id: TEAM_ID }, error: null }],
      team_members: [{ data: { role }, error: null }],
    });
    expect(await callerCanActFor(supabase, CALLER_ID, OWNER_ID)).toBe(true);
  });

  it.each(["auditor", "member"])("returns false for a read-only team '%s' member", async (role) => {
    const supabase = fakeSupabase({
      teams: [{ data: { id: TEAM_ID }, error: null }],
      team_members: [{ data: { role }, error: null }],
    });
    expect(await callerCanActFor(supabase, CALLER_ID, OWNER_ID)).toBe(false);
  });
});

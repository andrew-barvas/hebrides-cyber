import { describe, it, expect } from "vitest";
import { isPostDue, publishDuePosts } from "./blogSchedule";

describe("isPostDue", () => {
  const now = new Date("2026-06-15T12:00:00Z");

  it("is due when published_at is in the past", () => {
    expect(isPostDue("2026-06-15T11:59:59Z", now)).toBe(true);
  });

  it("is due exactly at the boundary", () => {
    expect(isPostDue("2026-06-15T12:00:00Z", now)).toBe(true);
  });

  it("is not due when published_at is in the future", () => {
    expect(isPostDue("2026-06-15T12:00:01Z", now)).toBe(false);
  });

  it("is never due for an unparseable date", () => {
    expect(isPostDue("not-a-date", now)).toBe(false);
  });
});

type Row = { slug: string; published_at: string | null };

function fakeSupabase(scheduled: Row[], opts: { selectError?: string; updateErrors?: Record<string, string> } = {}) {
  const updated: string[] = [];
  const supabase = {
    from: () => ({
      select: () => ({
        eq: async () => (opts.selectError ? { data: null, error: { message: opts.selectError } } : { data: scheduled, error: null }),
      }),
      update: () => ({
        eq: async (_col: string, slug: string) => {
          updated.push(slug);
          const err = opts.updateErrors?.[slug];
          return { error: err ? { message: err } : null };
        },
      }),
    }),
  };
  return { supabase, updated };
}

describe("publishDuePosts", () => {
  const now = new Date("2026-06-15T12:00:00Z");

  it("returns nothing_due when no scheduled posts exist", async () => {
    const { supabase } = fakeSupabase([]);
    const result = await publishDuePosts(supabase as never, now);
    expect(result).toEqual({ status: "nothing_due" });
  });

  it("returns nothing_due when every scheduled post is still in the future", async () => {
    const { supabase } = fakeSupabase([{ slug: "future-post", published_at: "2026-06-16T00:00:00Z" }]);
    const result = await publishDuePosts(supabase as never, now);
    expect(result).toEqual({ status: "nothing_due" });
  });

  it("publishes every due post and leaves future ones alone", async () => {
    const { supabase, updated } = fakeSupabase([
      { slug: "due-post", published_at: "2026-06-15T00:00:00Z" },
      { slug: "future-post", published_at: "2026-06-16T00:00:00Z" },
    ]);
    const result = await publishDuePosts(supabase as never, now);
    expect(result).toEqual({ status: "published", slugs: ["due-post"] });
    expect(updated).toEqual(["due-post"]);
  });

  it("never touches a row with a null published_at", async () => {
    const { supabase, updated } = fakeSupabase([{ slug: "broken", published_at: null }]);
    const result = await publishDuePosts(supabase as never, now);
    expect(result).toEqual({ status: "nothing_due" });
    expect(updated).toEqual([]);
  });

  it("returns an error without updating anything when the select fails", async () => {
    const { supabase, updated } = fakeSupabase([], { selectError: "db down" });
    const result = await publishDuePosts(supabase as never, now);
    expect(result).toEqual({ status: "error", error: "db down" });
    expect(updated).toEqual([]);
  });

  it("stops and reports the error if an update fails partway through", async () => {
    const { supabase, updated } = fakeSupabase(
      [
        { slug: "post-a", published_at: "2026-06-15T00:00:00Z" },
        { slug: "post-b", published_at: "2026-06-14T00:00:00Z" },
      ],
      { updateErrors: { "post-a": "constraint violation" } }
    );
    const result = await publishDuePosts(supabase as never, now);
    expect(result).toEqual({ status: "error", error: "post-a: constraint violation" });
    expect(updated).toEqual(["post-a"]);
  });

  it("defaults now to the current time when not supplied", async () => {
    const { supabase } = fakeSupabase([{ slug: "past", published_at: "2000-01-01T00:00:00Z" }]);
    const result = await publishDuePosts(supabase as never);
    expect(result).toEqual({ status: "published", slugs: ["past"] });
  });
});

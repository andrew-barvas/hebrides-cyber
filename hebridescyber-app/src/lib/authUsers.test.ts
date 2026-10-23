import { describe, it, expect, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { findAuthUserByEmail, USERS_PER_PAGE } from "./authUsers";

function adminWith(pages: Array<Array<{ email: string }>>, error?: string) {
  const listUsers = vi.fn(async ({ page }: { page: number }) =>
    error ? { data: { users: [] }, error: { message: error } } : { data: { users: pages[page - 1] ?? [] }, error: null }
  );
  return { admin: { auth: { admin: { listUsers } } } as unknown as SupabaseClient, listUsers };
}

const fullPage = Array.from({ length: USERS_PER_PAGE }, (_, i) => ({ email: `u${i}@x.com` }));

describe("findAuthUserByEmail", () => {
  it("matches case-insensitively on the first page", async () => {
    const { admin, listUsers } = adminWith([[{ email: "Me@Example.com" }]]);
    expect((await findAuthUserByEmail(admin, "me@example.com"))?.email).toBe("Me@Example.com");
    expect(listUsers).toHaveBeenCalledTimes(1);
  });

  it("keeps paging past a full page to find a later user", async () => {
    const { admin, listUsers } = adminWith([fullPage, [{ email: "late@x.com" }]]);
    expect((await findAuthUserByEmail(admin, "late@x.com"))?.email).toBe("late@x.com");
    expect(listUsers).toHaveBeenCalledTimes(2);
  });

  it("returns undefined once a short page is exhausted", async () => {
    const { admin } = adminWith([fullPage, [{ email: "a@x.com" }]]);
    expect(await findAuthUserByEmail(admin, "nobody@x.com")).toBeUndefined();
  });

  it("throws when listing fails rather than reporting 'not found'", async () => {
    const { admin } = adminWith([], "boom");
    await expect(findAuthUserByEmail(admin, "a@x.com")).rejects.toThrow("Could not list users: boom");
  });
});

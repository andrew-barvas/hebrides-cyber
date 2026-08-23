import { describe, it, expect, vi, beforeEach } from "vitest";

const { getUserMock } = vi.hoisted(() => ({ getUserMock: vi.fn() }));

// Minimal chainable Supabase query-builder stub, matching the pattern used
// throughout this suite (e.g. src/lib/freeTier.test.ts) — every chain
// method returns itself, and the chain resolves to `result` at
// .maybeSingle().
let profileResult: unknown = { data: null };

vi.mock("./supabaseAdmin", () => ({
  supabaseAdmin: {
    auth: { getUser: getUserMock },
    from: () => ({
      select: () => ({
        eq: () => ({
          maybeSingle: () => Promise.resolve(profileResult),
        }),
      }),
    }),
  },
}));

import { requireAdmin } from "./adminAuth";

function req(authorization?: string) {
  return { headers: authorization ? { authorization } : {} } as import("next").NextApiRequest;
}

describe("requireAdmin", () => {
  beforeEach(() => {
    getUserMock.mockReset();
    profileResult = { data: null };
  });

  it("returns null when there is no Authorization header", async () => {
    await expect(requireAdmin(req())).resolves.toBeNull();
    expect(getUserMock).not.toHaveBeenCalled();
  });

  it("returns null when the Authorization header isn't a Bearer token", async () => {
    await expect(requireAdmin(req("Basic abc123"))).resolves.toBeNull();
    expect(getUserMock).not.toHaveBeenCalled();
  });

  it("returns null when the token doesn't resolve to a user", async () => {
    getUserMock.mockResolvedValue({ data: { user: null }, error: null });
    await expect(requireAdmin(req("Bearer t"))).resolves.toBeNull();
  });

  it("returns null when getUser errors", async () => {
    getUserMock.mockResolvedValue({ data: { user: null }, error: { message: "invalid token" } });
    await expect(requireAdmin(req("Bearer t"))).resolves.toBeNull();
  });

  // The core of the gate this migration protects: is_admin === false (or
  // missing) must never resolve to an admin id, regardless of who's asking.
  it("returns null for an authenticated user whose profile is not admin", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "user-1" } }, error: null });
    profileResult = { data: { is_admin: false } };
    await expect(requireAdmin(req("Bearer t"))).resolves.toBeNull();
  });

  it("returns null when the profile row is missing entirely", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "user-1" } }, error: null });
    profileResult = { data: null };
    await expect(requireAdmin(req("Bearer t"))).resolves.toBeNull();
  });

  it("returns the user id for a real admin", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "admin-1" } }, error: null });
    profileResult = { data: { is_admin: true } };
    await expect(requireAdmin(req("Bearer t"))).resolves.toBe("admin-1");
  });

  // A missing SUPABASE_URL/SERVICE_ROLE_KEY throws inside supabaseAdmin's
  // lazy getter (per this function's own comment) — must degrade to "not an
  // admin" rather than an unhandled 500 in every admin route.
  it("returns null (not throwing) when the underlying call throws", async () => {
    getUserMock.mockRejectedValue(new Error("SUPABASE_SERVICE_ROLE_KEY is not set"));
    await expect(requireAdmin(req("Bearer t"))).resolves.toBeNull();
  });
});

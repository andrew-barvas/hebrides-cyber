import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mocked before importing auth.ts so its `import { supabase } from
// "./supabaseClient"` picks up this mock instead of constructing a real
// client (which would otherwise warn about missing env vars). vi.mock is
// hoisted above these declarations, so the mock fns themselves must be
// created via vi.hoisted() to be visible inside the factory.
const {
  getSessionMock,
  getUserMock,
  getAuthenticatorAssuranceLevelMock,
  signInWithOtpMock,
  resetPasswordForEmailMock,
  updateUserMock,
} = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  getUserMock: vi.fn(),
  getAuthenticatorAssuranceLevelMock: vi.fn(),
  signInWithOtpMock: vi.fn(),
  resetPasswordForEmailMock: vi.fn(),
  updateUserMock: vi.fn(),
}));

vi.mock("./supabaseClient", () => ({
  supabase: {
    auth: {
      getSession: getSessionMock,
      getUser: getUserMock,
      mfa: { getAuthenticatorAssuranceLevel: getAuthenticatorAssuranceLevelMock },
      signInWithOtp: signInWithOtpMock,
      resetPasswordForEmail: resetPasswordForEmailMock,
      updateUser: updateUserMock,
    },
  },
}));

import { getSession, getUser, getMfaAssuranceLevel, signInWithMagicLink, requestPasswordReset, updatePassword } from "./auth";

describe("auth.ts timeout wrapper", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    getSessionMock.mockReset();
    getUserMock.mockReset();
    getAuthenticatorAssuranceLevelMock.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("getSession resolves normally when the underlying call succeeds quickly", async () => {
    const fakeSession = { access_token: "abc", user: { id: "u1" } };
    getSessionMock.mockResolvedValue({ data: { session: fakeSession }, error: null });

    const result = await getSession();
    expect(result).toBe(fakeSession);
  });

  it("getSession returns null when supabase reports an error", async () => {
    getSessionMock.mockResolvedValue({ data: { session: null }, error: { message: "boom" } });

    const result = await getSession();
    expect(result).toBeNull();
  });

  // Regression test for the production bug: a stuck cross-tab
  // navigator.locks mutex inside supabase-js makes getSession() never
  // resolve at all — every page gating its "loading" state on this call
  // would otherwise spin forever until the user manually refreshes. This
  // simulates that by giving getSession a promise that never settles, and
  // asserting the wrapper still resolves (to null) once its timeout fires.
  it("getSession resolves to null instead of hanging forever when the underlying call never settles", async () => {
    getSessionMock.mockReturnValue(new Promise(() => {})); // never resolves — simulates a stuck auth lock

    const pending = getSession();
    await vi.advanceTimersByTimeAsync(8_000);

    await expect(pending).resolves.toBeNull();
  });

  it("getUser resolves to null instead of hanging forever when the underlying call never settles", async () => {
    getUserMock.mockReturnValue(new Promise(() => {}));

    const pending = getUser();
    await vi.advanceTimersByTimeAsync(8_000);

    await expect(pending).resolves.toBeNull();
  });

  it("getMfaAssuranceLevel resolves to the safe default instead of hanging forever", async () => {
    getAuthenticatorAssuranceLevelMock.mockReturnValue(new Promise(() => {}));

    const pending = getMfaAssuranceLevel();
    await vi.advanceTimersByTimeAsync(8_000);

    await expect(pending).resolves.toEqual({ currentLevel: null, nextLevel: null });
  });

  it("getMfaAssuranceLevel returns the safe default when the underlying call throws synchronously", async () => {
    getAuthenticatorAssuranceLevelMock.mockRejectedValue(new Error("AuthInvalidJwtError"));

    const result = await getMfaAssuranceLevel();
    expect(result).toEqual({ currentLevel: null, nextLevel: null });
  });

  it("does not fire its timeout once the underlying call has already resolved", async () => {
    getSessionMock.mockResolvedValue({ data: { session: null }, error: null });

    await getSession();
    // If the timer weren't cleared, advancing past it would be harmless
    // here anyway since the promise already settled — this asserts no
    // stray timer throws/console noise when fake timers are torn down.
    await vi.advanceTimersByTimeAsync(8_000);
  });
});

describe("signInWithMagicLink", () => {
  beforeEach(() => {
    signInWithOtpMock.mockReset().mockResolvedValue({ error: null });
  });

  it("passes no metadata by default (a returning user's sign-in)", async () => {
    await signInWithMagicLink("a@example.com");
    expect(signInWithOtpMock).toHaveBeenCalledWith({
      email: "a@example.com",
      options: expect.objectContaining({ data: undefined }),
    });
  });

  // Regression test: metadata passed here must reach raw_user_meta_data so
  // migration 059's handle_new_user() trigger can read company_name out of
  // it when creating a brand-new public.users profile row.
  it("forwards metadata (e.g. company_name) for the sign-up flow to pick up", async () => {
    await signInWithMagicLink("a@example.com", { company_name: "Acme" });
    expect(signInWithOtpMock).toHaveBeenCalledWith({
      email: "a@example.com",
      options: expect.objectContaining({ data: { company_name: "Acme" } }),
    });
  });
});

describe("requestPasswordReset / updatePassword", () => {
  it("requests a reset email that redirects through the auth callback to /reset-password", async () => {
    resetPasswordForEmailMock.mockResolvedValue({ error: null });
    await requestPasswordReset("a@example.com");
    expect(resetPasswordForEmailMock).toHaveBeenCalledWith(
      "a@example.com",
      expect.objectContaining({ redirectTo: expect.stringContaining("/auth/callback?next=/reset-password") })
    );
  });

  it("updates the password via supabase.auth.updateUser", async () => {
    updateUserMock.mockResolvedValue({ error: null });
    await updatePassword("new-password-123");
    expect(updateUserMock).toHaveBeenCalledWith({ password: "new-password-123" });
  });
});

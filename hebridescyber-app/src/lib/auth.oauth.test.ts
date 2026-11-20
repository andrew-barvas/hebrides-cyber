import { describe, it, expect, vi, beforeEach } from "vitest";

const a = vi.hoisted(() => ({
  signInWithOAuth: vi.fn(),
  signInWithPassword: vi.fn(),
  signOut: vi.fn(),
  listFactors: vi.fn(),
  enroll: vi.fn(),
  challenge: vi.fn(),
  verify: vi.fn(),
  unenroll: vi.fn(),
}));

vi.mock("./supabaseClient", () => ({
  supabase: {
    auth: {
      signInWithOAuth: a.signInWithOAuth,
      signInWithPassword: a.signInWithPassword,
      signOut: a.signOut,
      mfa: { listFactors: a.listFactors, enroll: a.enroll, challenge: a.challenge, verify: a.verify, unenroll: a.unenroll },
    },
  },
}));

import { challengeMfaFactor, enrollMfaTotp, listMfaFactors, signInWithGoogle, signInWithPassword, signOut, unenrollMfaFactor, verifyMfaFactor } from "./auth";

describe("signInWithGoogle (#273)", () => {
  beforeEach(() => {
    a.signInWithOAuth.mockReset().mockResolvedValue({ data: {}, error: null });
  });

  it("returns through /auth/callback, carrying a safe next path", async () => {
    await signInWithGoogle("/pricing?plan=pro");
    expect(a.signInWithOAuth).toHaveBeenCalledWith({ provider: "google", options: { redirectTo: `${window.location.origin}/auth/callback?next=${encodeURIComponent("/pricing?plan=pro")}` } });
  });

  it("drops the default and unsafe next paths", async () => {
    await signInWithGoogle("/dashboard");
    await signInWithGoogle();
    await signInWithGoogle("https://evil.example/");
    const targets = a.signInWithOAuth.mock.calls.map((c) => c[0].options.redirectTo as string);
    expect(targets[0]).toBe(`${window.location.origin}/auth/callback`);
    expect(targets[1]).toBe(`${window.location.origin}/auth/callback`);
    expect(targets[2]).not.toContain("evil.example");
  });
});

describe("thin auth wrappers", () => {
  it("pass straight through to Supabase", async () => {
    a.signInWithPassword.mockResolvedValue({ error: null });
    a.signOut.mockResolvedValue({ error: null });
    a.enroll.mockResolvedValue({ data: { id: "f" } });
    a.challenge.mockResolvedValue({ data: { id: "c" } });
    a.verify.mockResolvedValue({ data: {} });
    a.unenroll.mockResolvedValue({ data: {} });
    await signInWithPassword("a@x.test", "pw");
    await signOut();
    await enrollMfaTotp();
    await challengeMfaFactor("f");
    await verifyMfaFactor("f", "c", "123456");
    await unenrollMfaFactor("f");
    expect(a.signInWithPassword).toHaveBeenCalledWith({ email: "a@x.test", password: "pw" });
    expect(a.enroll).toHaveBeenCalledWith({ factorType: "totp" });
    expect(a.challenge).toHaveBeenCalledWith({ factorId: "f" });
    expect(a.verify).toHaveBeenCalledWith({ factorId: "f", challengeId: "c", code: "123456" });
    expect(a.unenroll).toHaveBeenCalledWith({ factorId: "f" });
  });

  it("listMfaFactors returns the factors, or none on error", async () => {
    a.listFactors.mockResolvedValueOnce({ data: { totp: [{ id: "f" }] }, error: null });
    expect(await listMfaFactors()).toEqual({ totp: [{ id: "f" }] });
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    a.listFactors.mockResolvedValueOnce({ data: null, error: { message: "boom" } });
    expect(await listMfaFactors()).toEqual({ totp: [] });
    err.mockRestore();
  });
});

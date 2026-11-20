import { describe, it, expect } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { bearerToken, hashDeviceToken, isWellFormedDeviceToken, mintDeviceToken, resolveDeviceToken, DEVICE_TOKEN_RE } from "./tokens";

function dbReturning(result: { data: unknown; error: unknown }) {
  const calls: Array<[string, unknown]> = [];
  const builder = {
    select: () => builder,
    eq: (col: string, val: unknown) => {
      calls.push([col, val]);
      return builder;
    },
    maybeSingle: () => Promise.resolve(result),
  };
  return { db: { from: () => builder } as unknown as SupabaseClient, calls };
}

describe("device tokens", () => {
  it("mints hcd_ tokens of the shape the Go agent accepts, stored only as a SHA-256 hash", () => {
    const t = mintDeviceToken();
    expect(t.plaintext).toMatch(DEVICE_TOKEN_RE);
    expect(t.plaintext).toHaveLength(47);
    expect(t.token_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(t.token_hash).toBe(hashDeviceToken(t.plaintext));
    expect(t.token_hash).not.toContain(t.plaintext.slice(4));
    expect(t.token_prefix).toBe(t.plaintext.slice(0, 12));
    expect(mintDeviceToken().plaintext).not.toBe(t.plaintext);
  });

  it("tells well-formed tokens apart from API keys and junk", () => {
    expect(isWellFormedDeviceToken(mintDeviceToken().plaintext)).toBe(true);
    for (const bad of ["", "hc_live_abc", "hcd_short", `hcd_${"a".repeat(44)}`, `hcd_${"!".repeat(43)}`]) {
      expect(isWellFormedDeviceToken(bad)).toBe(false);
    }
  });

  it("reads a bearer token from the Authorization header only", () => {
    expect(bearerToken("Bearer abc ")).toBe("abc");
    expect(bearerToken(["Bearer x", "Bearer y"])).toBe("x");
    expect(bearerToken("Basic abc")).toBeNull();
    expect(bearerToken("Bearer   ")).toBeNull();
    expect(bearerToken(undefined)).toBeNull();
  });

  describe("resolveDeviceToken", () => {
    const token = mintDeviceToken();
    const row = { id: "d1", owner: "o1", name: "PC", token_hash: token.token_hash, revoked_at: null, pending_first_seen: { "apt:x": "2026-11-01" }, last_match: null, matched_at: null };

    it("looks the device up by the token's hash, never the plaintext", async () => {
      const { db, calls } = dbReturning({ data: row, error: null });
      const res = await resolveDeviceToken(db, token.plaintext);
      expect(calls).toEqual([["token_hash", token.token_hash]]);
      expect(res).toEqual({ ok: true, device: { id: "d1", owner: "o1", name: "PC", pending_first_seen: { "apt:x": "2026-11-01" }, last_match: null, matched_at: null } });
    });

    it("refuses revoked and unknown tokens", async () => {
      expect(await resolveDeviceToken(dbReturning({ data: { ...row, revoked_at: "2026-11-02" }, error: null }).db, token.plaintext)).toEqual({ ok: false, reason: "revoked" });
      expect(await resolveDeviceToken(dbReturning({ data: null, error: null }).db, token.plaintext)).toEqual({ ok: false, reason: "unknown" });
      expect(await resolveDeviceToken(dbReturning({ data: { ...row, token_hash: "0".repeat(64) }, error: null }).db, token.plaintext)).toEqual({ ok: false, reason: "unknown" });
    });

    it("reports a database error as an error, not as an unknown token", async () => {
      const res = await resolveDeviceToken(dbReturning({ data: null, error: { code: "42P01", message: "missing" } }).db, token.plaintext);
      expect(res).toMatchObject({ ok: false, reason: "error" });
    });

    it("treats a malformed first-seen map as empty", async () => {
      const res = await resolveDeviceToken(dbReturning({ data: { ...row, pending_first_seen: ["x"], last_match: undefined }, error: null }).db, token.plaintext);
      expect(res).toMatchObject({ ok: true, device: { pending_first_seen: {}, last_match: null } });
    });
  });
});

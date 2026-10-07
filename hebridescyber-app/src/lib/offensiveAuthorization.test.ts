import { describe, it, expect } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { authHostFromUrl, isAuthorizationCurrent, hasActiveOffensiveAuthorization } from "./offensiveAuthorization";

describe("authHostFromUrl", () => {
  it("lowercases the hostname and rejects a non-URL", () => {
    expect(authHostFromUrl("https://Example.com/path?q=1")).toBe("example.com");
    expect(authHostFromUrl("http://sub.EXAMPLE.co.uk")).toBe("sub.example.co.uk");
    expect(authHostFromUrl("not a url")).toBeNull();
  });
});

describe("isAuthorizationCurrent", () => {
  const now = new Date("2026-10-07T12:00:00Z");
  it("true only when not revoked and not expired", () => {
    expect(isAuthorizationCurrent({ revoked_at: null, expires_at: null }, now)).toBe(true);
    expect(isAuthorizationCurrent({ revoked_at: null, expires_at: "2026-12-01T00:00:00Z" }, now)).toBe(true);
    expect(isAuthorizationCurrent({ revoked_at: "2026-10-06T00:00:00Z", expires_at: null }, now)).toBe(false);
    expect(isAuthorizationCurrent({ revoked_at: null, expires_at: "2026-10-01T00:00:00Z" }, now)).toBe(false);
    // expiry exactly now counts as expired
    expect(isAuthorizationCurrent({ revoked_at: null, expires_at: "2026-10-07T12:00:00Z" }, now)).toBe(false);
  });
});

// Minimal fake for the read chain hasActiveOffensiveAuthorization uses:
// .from().select().eq().eq().is().order().limit().maybeSingle()
function readClient(result: { data: unknown; error?: unknown }): SupabaseClient {
  const chain: Record<string, unknown> = {};
  for (const m of ["select", "eq", "is", "order", "limit"]) chain[m] = () => chain;
  chain.maybeSingle = () => Promise.resolve(result);
  return { from: () => chain } as unknown as SupabaseClient;
}

describe("hasActiveOffensiveAuthorization", () => {
  const now = new Date("2026-10-07T12:00:00Z");

  it("false for an invalid URL without touching the DB", async () => {
    let touched = false;
    const spy = { from: () => { touched = true; return {}; } } as unknown as SupabaseClient;
    expect(await hasActiveOffensiveAuthorization(spy, "o", "not a url", now)).toBe(false);
    expect(touched).toBe(false);
  });

  it("true for a current row", async () => {
    const client = readClient({ data: { revoked_at: null, expires_at: null }, error: null });
    expect(await hasActiveOffensiveAuthorization(client, "o", "https://example.com", now)).toBe(true);
  });

  it("false when no row, on a read error, or before the table exists (missing schema)", async () => {
    expect(await hasActiveOffensiveAuthorization(readClient({ data: null, error: null }), "o", "https://example.com", now)).toBe(false);
    expect(await hasActiveOffensiveAuthorization(readClient({ data: null, error: { message: "boom" } }), "o", "https://example.com", now)).toBe(false);
    expect(await hasActiveOffensiveAuthorization(readClient({ data: null, error: { code: "42P01", message: "relation does not exist" } }), "o", "https://example.com", now)).toBe(false);
  });

  it("false for an expired row even if returned", async () => {
    const client = readClient({ data: { revoked_at: null, expires_at: "2026-01-01T00:00:00Z" }, error: null });
    expect(await hasActiveOffensiveAuthorization(client, "o", "https://example.com", now)).toBe(false);
  });
});

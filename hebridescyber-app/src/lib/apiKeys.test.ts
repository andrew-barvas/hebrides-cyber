import { describe, it, expect, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { hashApiKey, mintApiKey, looksLikeApiKey, resolveApiKey, recordBlockedApiKeyUse } from "./apiKeys";

describe("hashApiKey", () => {
  it("is a stable 64-hex SHA-256 of the plaintext, not the plaintext", () => {
    const h = hashApiKey("hc_live_abc");
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(h).toBe(hashApiKey("hc_live_abc"));
    expect(h).not.toBe(hashApiKey("hc_live_abd"));
  });
});

describe("mintApiKey", () => {
  it("mints a prefixed high-entropy key whose hash and prefix match the plaintext", () => {
    const k = mintApiKey();
    expect(k.plaintext.startsWith("hc_live_")).toBe(true);
    expect(k.plaintext.length).toBeGreaterThan(40);
    expect(k.key_hash).toBe(hashApiKey(k.plaintext));
    expect(k.key_prefix).toBe(k.plaintext.slice(0, 16));
  });

  it("mints a different key each time", () => {
    expect(mintApiKey().plaintext).not.toBe(mintApiKey().plaintext);
  });
});

describe("looksLikeApiKey", () => {
  it("matches only the live prefix", () => {
    expect(looksLikeApiKey("hc_live_xyz")).toBe(true);
    expect(looksLikeApiKey("Bearer hc_live_xyz")).toBe(false);
    expect(looksLikeApiKey("eyJhbGci...")).toBe(false);
  });
});

/** Minimal Supabase stub: records calls and returns a scripted row for the
 *  select chain; the update chain is then-able (resolveApiKey fires telemetry
 *  via .then without awaiting). */
function fakeSupabase(row: Record<string, unknown> | null) {
  const updateChain = {
    eq: vi.fn(() => ({ then: (res: () => void) => Promise.resolve().then(res) })),
  };
  const update = vi.fn(() => updateChain);
  const select = vi.fn(() => ({
    eq: vi.fn(() => ({ maybeSingle: vi.fn(async () => ({ data: row })) })),
  }));
  const from = vi.fn(() => ({ select, update }));
  return { client: { from } as unknown as SupabaseClient, from, select, update };
}

describe("resolveApiKey", () => {
  it("resolves a live key to its owner and allowlist", async () => {
    const plaintext = "hc_live_sometoken";
    const row = { owner: "owner-1", id: "key-1", key_hash: hashApiKey(plaintext), revoked_at: null, allowed_cidrs: ["10.0.0.0/8"] };
    const { client } = fakeSupabase(row);
    const result = await resolveApiKey(client, plaintext);
    // No scopes column stored (pre-063 row) → full access, i.e. the behaviour before scopes existed.
    expect(result).toEqual({ ownerId: "owner-1", keyId: "key-1", allowedCidrs: ["10.0.0.0/8"], scopes: ["scans:read", "scans:write", "dependency:check"] });
  });

  it("returns the scopes stored on the key, dropping anything unrecognised", async () => {
    const plaintext = "hc_live_sometoken";
    const row = { owner: "o", id: "k", key_hash: hashApiKey(plaintext), revoked_at: null, scopes: ["scans:read", "admin:everything"] };
    const result = await resolveApiKey(fakeSupabase(row).client, plaintext);
    expect(result?.scopes).toEqual(["scans:read"]);
  });

  it("returns null for an unknown key", async () => {
    const { client } = fakeSupabase(null);
    expect(await resolveApiKey(client, "hc_live_nope")).toBeNull();
  });

  it("returns null for a revoked key", async () => {
    const plaintext = "hc_live_revoked";
    const row = { owner: "o", id: "k", key_hash: hashApiKey(plaintext), revoked_at: "2026-01-01T00:00:00Z", allowed_cidrs: [] };
    const { client } = fakeSupabase(row);
    expect(await resolveApiKey(client, plaintext)).toBeNull();
  });

  it("returns null when the stored hash doesn't match (defence in depth)", async () => {
    // Row returned but its key_hash is for a different key — the constant-time
    // compare rejects it.
    const row = { owner: "o", id: "k", key_hash: hashApiKey("hc_live_other"), revoked_at: null, allowed_cidrs: [] };
    const { client } = fakeSupabase(row);
    expect(await resolveApiKey(client, "hc_live_mine")).toBeNull();
  });

  it("defaults the allowlist to [] when the column is absent (unmigrated DB)", async () => {
    const plaintext = "hc_live_nocidrs";
    const row = { owner: "o", id: "k", key_hash: hashApiKey(plaintext), revoked_at: null };
    const { client } = fakeSupabase(row);
    const result = await resolveApiKey(client, plaintext);
    expect(result?.allowedCidrs).toEqual([]);
  });

  it("records last-used telemetry without awaiting it", async () => {
    const plaintext = "hc_live_used";
    const row = { owner: "o", id: "key-9", key_hash: hashApiKey(plaintext), revoked_at: null, allowed_cidrs: [] };
    const { client, update } = fakeSupabase(row);
    await resolveApiKey(client, plaintext);
    expect(update).toHaveBeenCalledWith(expect.objectContaining({ last_used_at: expect.any(String) }));
  });
});

describe("recordBlockedApiKeyUse", () => {
  it("writes the truncated IP and a timestamp, never throwing", async () => {
    const { client, update } = fakeSupabase(null);
    await expect(recordBlockedApiKeyUse(client, "key-1", "203.0.113.5")).resolves.toBeUndefined();
    expect(update).toHaveBeenCalledWith(expect.objectContaining({ last_blocked_ip: "203.0.113.5", last_blocked_at: expect.any(String) }));
  });

  it("swallows a DB error (telemetry only)", async () => {
    const throwing = { from: () => ({ update: () => ({ eq: () => Promise.reject(new Error("db down")) }) }) } as unknown as SupabaseClient;
    await expect(recordBlockedApiKeyUse(throwing, "key-1", "1.2.3.4")).resolves.toBeUndefined();
  });
});

import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { hashApiKey, mintApiKey } from "./apiKeys";

type Update = { values: Record<string, unknown>; eq: [string, unknown][]; executed: boolean };

const state: { row: Record<string, unknown> | null; updates: Update[] } = { row: null, updates: [] };
const { getUserMock } = vi.hoisted(() => ({ getUserMock: vi.fn() }));

// PostgREST builders only send their request from then() — the stub models
// that, so a query that is built but never then()'d shows executed: false.
function makeBuilder() {
  let pending: Update | null = null;
  const builder: Record<string, unknown> = {
    select: () => builder,
    update: (values: Record<string, unknown>) => {
      pending = { values, eq: [], executed: false };
      state.updates.push(pending);
      return builder;
    },
    eq: (col: string, val: unknown) => {
      pending?.eq.push([col, val]);
      return builder;
    },
    maybeSingle: () => Promise.resolve({ data: state.row, error: null }),
    then: (onFulfilled?: (v: unknown) => unknown, onRejected?: (e: unknown) => unknown) => {
      if (pending) pending.executed = true;
      return Promise.resolve({ data: null, error: null }).then(onFulfilled, onRejected);
    },
  };
  return builder;
}

vi.mock("./supabaseAdmin", () => {
  const client = { from: () => makeBuilder(), auth: { getUser: getUserMock } };
  return { getSupabaseAdmin: () => client, supabaseAdmin: client };
});

import { authenticateApiRequest } from "./apiAuth";

const { plaintext: KEY } = mintApiKey();

function keyRow(extra: Record<string, unknown> = {}) {
  return { id: "key-1", owner: "owner-1", key_hash: hashApiKey(KEY), revoked_at: null, ...extra };
}

function request(token: string, ip = "203.0.113.7") {
  return createMocks<NextApiRequest, NextApiResponse>({
    headers: { authorization: `Bearer ${token}`, "x-forwarded-for": ip },
  }).req;
}

const flush = () => new Promise((r) => setTimeout(r, 0));

describe("authenticateApiRequest", () => {
  beforeEach(() => {
    state.row = null;
    state.updates = [];
    getUserMock.mockReset();
  });

  it("returns null without a bearer token", async () => {
    const { req } = createMocks<NextApiRequest, NextApiResponse>();
    expect(await authenticateApiRequest(req)).toBeNull();
  });

  it("resolves a session JWT", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "owner-1" } }, error: null });
    expect(await authenticateApiRequest(request("eyJ.jwt"))).toEqual({ ownerId: "owner-1", via: "session" });
  });

  it("resolves an unrestricted key and records last_used_at", async () => {
    state.row = keyRow({ allowed_cidrs: [] });
    expect(await authenticateApiRequest(request(KEY))).toEqual({ ownerId: "owner-1", via: "key" });
    await flush();
    // Regression: this write was `void builder` and never ran.
    const touch = state.updates.find((u) => "last_used_at" in u.values);
    expect(touch?.executed).toBe(true);
  });

  // Before migration 042 the row has no allowed_cidrs at all.
  it("treats a row without the allowlist column as unrestricted", async () => {
    state.row = keyRow();
    expect(await authenticateApiRequest(request(KEY))).toEqual({ ownerId: "owner-1", via: "key" });
  });

  it("rejects a revoked key", async () => {
    state.row = keyRow({ revoked_at: "2026-09-01T00:00:00Z" });
    expect(await authenticateApiRequest(request(KEY))).toBeNull();
  });

  it("accepts a key from an allowed address", async () => {
    state.row = keyRow({ allowed_cidrs: ["203.0.113.0/24"] });
    expect(await authenticateApiRequest(request(KEY, "203.0.113.7"))).toEqual({ ownerId: "owner-1", via: "key" });
    expect(state.updates.some((u) => "last_blocked_ip" in u.values)).toBe(false);
  });

  it("refuses a key from any other address, and records the refusal", async () => {
    state.row = keyRow({ allowed_cidrs: ["203.0.113.0/24"] });
    expect(await authenticateApiRequest(request(KEY, "198.51.100.9"))).toBeNull();
    const blocked = state.updates.find((u) => "last_blocked_ip" in u.values);
    expect(blocked?.executed).toBe(true);
    expect(blocked?.values.last_blocked_ip).toBe("198.51.100.9");
    expect(blocked?.eq).toContainEqual(["id", "key-1"]);
  });

  it("never IP-restricts a session — the allowlist belongs to a key", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "owner-1" } }, error: null });
    state.row = keyRow({ allowed_cidrs: ["203.0.113.0/24"] });
    expect(await authenticateApiRequest(request("eyJ.jwt", "198.51.100.9"))).not.toBeNull();
  });
});

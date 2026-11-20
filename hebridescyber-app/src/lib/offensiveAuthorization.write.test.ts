import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";

const { auditMock } = vi.hoisted(() => ({ auditMock: vi.fn() }));
vi.mock("./audit", () => ({ logAuditEvent: auditMock }));

import { recordOffensiveAuthorization, revokeOffensiveAuthorization } from "./offensiveAuthorization";

const NOW = new Date("2026-11-20T12:00:00Z");
const EXP = "2026-12-01T00:00:00Z";
const MISSING = { code: "42P01", message: 'relation "offensive_scan_authorizations" does not exist' };

type Result = { error: unknown };
function client(opts: { update?: Result; insert?: Result; throws?: boolean } = {}) {
  const inserted: unknown[] = [];
  const c = {
    from: () => {
      if (opts.throws) throw new Error("network");
      const chain: Record<string, unknown> = {
        eq: () => chain,
        is: async () => opts.update ?? { error: null },
      };
      return {
        update: () => chain,
        insert: async (row: unknown) => {
          inserted.push(row);
          return opts.insert ?? { error: null };
        },
      };
    },
  } as unknown as SupabaseClient;
  return { c, inserted };
}

const params = { owner: "o1", authorizedBy: "o1", targetUrl: "https://www.example.com/", scope: "s", expiresAt: EXP };

describe("recordOffensiveAuthorization", () => {
  beforeEach(() => {
    auditMock.mockReset();
  });

  it("revokes the previous one, records the new one with its expiry, and audits it", async () => {
    const { c, inserted } = client();
    expect(await recordOffensiveAuthorization(c, params, NOW)).toEqual({ ok: true, host: "www.example.com", expiresAt: "2026-12-01T00:00:00.000Z" });
    expect(inserted).toEqual([{ owner: "o1", target_host: "www.example.com", authorized_by: "o1", scope: "s", expires_at: "2026-12-01T00:00:00.000Z" }]);
    expect(auditMock).toHaveBeenCalledWith(c, expect.objectContaining({ action: "offensive_scan.authorized", resourceId: "www.example.com" }));
  });

  it("rejects a bad URL before anything else", async () => {
    expect(await recordOffensiveAuthorization(client().c, { ...params, targetUrl: "not a url" }, NOW)).toEqual({ ok: false, reason: "invalid_url" });
  });

  it.each([
    ["the revoke", { update: { error: MISSING } }, "unavailable"],
    ["the revoke", { update: { error: { message: "boom" } } }, "error"],
    ["the insert", { insert: { error: MISSING } }, "unavailable"],
    ["the insert", { insert: { error: { message: "boom" } } }, "error"],
    ["the client", { throws: true }, "error"],
  ])("maps a failure in %s to %s", async (_where, opts, reason) => {
    expect(await recordOffensiveAuthorization(client(opts).c, params, NOW)).toEqual({ ok: false, reason });
    expect(auditMock).not.toHaveBeenCalled();
  });
});

describe("revokeOffensiveAuthorization", () => {
  beforeEach(() => {
    auditMock.mockReset();
  });

  it("revokes and audits", async () => {
    expect(await revokeOffensiveAuthorization(client().c, { owner: "o1", actorId: "o1", targetUrl: "https://www.example.com" })).toEqual({ ok: true, host: "www.example.com" });
    expect(auditMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "offensive_scan.revoked" }));
  });

  it.each([
    [{ update: { error: MISSING } }, "unavailable"],
    [{ update: { error: { message: "boom" } } }, "error"],
    [{ throws: true }, "error"],
  ])("maps failures (%o) to %s", async (opts, reason) => {
    expect(await revokeOffensiveAuthorization(client(opts).c, { owner: "o1", actorId: "o1", targetUrl: "https://www.example.com" })).toEqual({ ok: false, reason });
  });

  it("rejects a bad URL", async () => {
    expect(await revokeOffensiveAuthorization(client().c, { owner: "o1", actorId: "o1", targetUrl: "::" })).toEqual({ ok: false, reason: "invalid_url" });
  });
});

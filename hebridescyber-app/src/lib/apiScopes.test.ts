import { describe, it, expect } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiResponse } from "next";
import { API_KEY_PRESETS, API_SCOPES, hasScope, isApiScope, requireScope, scopesFromRow } from "./apiScopes";

function res() {
  return createMocks<never, NextApiResponse>().res;
}

describe("apiScopes", () => {
  it("treats a caller with no scopes (a session) as unrestricted", () => {
    expect(hasScope({}, "scans:write")).toBe(true);
  });

  it("allows only the scopes a key holds", () => {
    expect(hasScope({ scopes: ["scans:read"] }, "scans:read")).toBe(true);
    expect(hasScope({ scopes: ["scans:read"] }, "scans:write")).toBe(false);
  });

  it("answers 403 insufficient_scope naming the missing scope", () => {
    const r = res();
    expect(requireScope({ scopes: ["scans:read"] }, r, "scans:write")).toBe(false);
    expect(r.statusCode).toBe(403);
    expect(r._getJSONData()).toMatchObject({ code: "insufficient_scope", required_scope: "scans:write" });
  });

  it("stays silent when allowed", () => {
    const r = res();
    expect(requireScope({ scopes: ["scans:write"] }, r, "scans:write")).toBe(true);
    expect(r._isEndCalled()).toBe(false);
  });

  it("reads stored scopes defensively: absent column means full access, junk is dropped", () => {
    expect(scopesFromRow(undefined)).toEqual([...API_SCOPES]);
    expect(scopesFromRow(["scans:read", "nope", 3])).toEqual(["scans:read"]);
    expect(isApiScope("scans:read")).toBe(true);
    expect(isApiScope("scans:delete")).toBe(false);
  });

  it("every preset uses only known scopes, read_only grants no write, and full is everything", () => {
    for (const p of Object.values(API_KEY_PRESETS)) for (const s of p.scopes) expect(isApiScope(s)).toBe(true);
    expect(API_KEY_PRESETS.read_only.scopes).toEqual(["scans:read"]);
    expect(API_KEY_PRESETS.full.scopes).toEqual([...API_SCOPES]);
  });
});

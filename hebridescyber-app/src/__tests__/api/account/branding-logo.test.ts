// White-label branding is Agency-only, decided by planAccess.ts: only an
// active subscription counts, whatever `plan` still says.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, updates } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  updates: [] as Record<string, unknown>[],
}));

let queues: Record<string, unknown[]> = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    update: (row: Record<string, unknown>) => {
      updates.push(row);
      return builder;
    },
    single: next,
    maybeSingle: next,
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));

import handler from "@/pages/api/account/branding-logo";

function post(body: Record<string, unknown>) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "POST", body });
}

describe("POST /api/account/branding-logo", () => {
  beforeEach(() => {
    queues = {};
    updates.length = 0;
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
  });

  it.each([
    ["Pro", { plan: "pro", status: "active" }],
    ["a cancelled Agency", { plan: "agency", status: "cancelled" }],
    ["a past-due Agency", { plan: "agency", status: "past_due" }],
  ])("refuses %s subscription and writes nothing", async (_label, row) => {
    queues.subscriptions = [{ data: row, error: null }];
    const { req, res } = post({ brandName: "Acme" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
    expect(updates).toHaveLength(0);
  });

  it("refuses an API-key caller before checking the plan", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "key" });
    const { req, res } = post({ brandName: "Acme" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
    expect(queues.subscriptions).toBeUndefined();
  });

  it("answers 500 when the plan can't be read", async () => {
    queues.subscriptions = [{ data: null, error: { message: "down" } }];
    const { req, res } = post({ brandName: "Acme" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(500);
  });

  it("saves the brand name for an active Agency subscription", async () => {
    queues.subscriptions = [
      { data: { plan: "agency", status: "active" }, error: null },
      { data: { brand_logo_url: null, brand_name: "Acme" }, error: null },
    ];
    const { req, res } = post({ brandName: "  Acme  " });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(updates).toEqual([{ brand_name: "Acme" }]);
  });
});

import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, loadMock, canViewMock, listMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  loadMock: vi.fn(),
  canViewMock: vi.fn(),
  listMock: vi.fn(),
}));

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authenticateApiRequestMock, supabaseAdmin: { tag: "admin" } }));
vi.mock("@/lib/findingsView", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/lib/findingsView")>()), loadFindingsView: loadMock }));
vi.mock("@/lib/teamAccess", () => ({ callerCanView: canViewMock, listViewableAccounts: listMock }));

import findings from "@/pages/api/findings/index";
import accounts from "@/pages/api/findings/accounts";

const ME = "11111111-1111-4111-8111-111111111111";
const BOSS = "22222222-2222-4222-8222-222222222222";

async function call(handler: typeof findings, query: Record<string, string> = {}) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query });
  await handler(req, res);
  return { status: res._getStatusCode(), body: JSON.parse(res._getData() || "{}") as Record<string, unknown>, req };
}

const mine = { key: "a.example x", host: "a.example", checkId: "x", checkBase: "x", category: "headers", severity: "high", title: "Mine", triage: null, assignee: { id: ME, email: "me@example.com" } };
const theirs = { ...mine, key: "a.example y", checkId: "y", checkBase: "y", title: "Not mine", assignee: null };

describe("team members reading the owner's findings", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: ME, via: "session" });
    canViewMock.mockReset().mockResolvedValue(true);
    listMock.mockReset().mockResolvedValue([{ ownerId: BOSS, email: "boss@example.com", role: "member" }]);
    loadMock.mockReset().mockResolvedValue({
      ok: true,
      data: { available: true, triageAvailable: true, slaEnabled: false, detailComplete: true, truncated: false, rows: [mine, theirs], detailByHost: new Map() },
    });
  });

  it("serves the owner's list, read-only, to a member of their team", async () => {
    const { status, body } = await call(findings, { account: BOSS, view: "rows" });
    expect(status).toBe(200);
    expect(loadMock).toHaveBeenCalledWith({ tag: "admin" }, BOSS);
    expect(canViewMock).toHaveBeenCalledWith({ tag: "admin" }, ME, BOSS);
    expect(body.readOnly).toBe(true);
  });

  it("filters to what's assigned to the caller with assignee=me", async () => {
    const { body } = await call(findings, { account: BOSS, view: "rows", assignee: "me", triage: "all" });
    expect((body.items as Array<{ title: string }>).map((i) => i.title)).toEqual(["Mine"]);
  });

  it("refuses someone not on the team, an API key and a malformed id", async () => {
    canViewMock.mockResolvedValue(false);
    expect((await call(findings, { account: BOSS })).status).toBe(404);
    canViewMock.mockResolvedValue(true);
    authenticateApiRequestMock.mockResolvedValue({ ownerId: ME, via: "api_key" });
    expect((await call(findings, { account: BOSS })).status).toBe(403);
    authenticateApiRequestMock.mockResolvedValue({ ownerId: ME, via: "session" });
    expect((await call(findings, { account: "not-an-id" })).status).toBe(400);
    expect(loadMock).not.toHaveBeenCalled();
  });

  it("treats the caller's own id as their own account, not read-only", async () => {
    const { body } = await call(findings, { account: ME });
    expect(body.readOnly).toBe(false);
    expect(canViewMock).not.toHaveBeenCalled();
  });

  it("lists the caller's own account first, then their teams", async () => {
    const { body } = await call(accounts);
    expect(body.accounts).toEqual([
      { ownerId: ME, email: null, role: "owner", own: true },
      { ownerId: BOSS, email: "boss@example.com", role: "member", own: false },
    ]);
  });
});

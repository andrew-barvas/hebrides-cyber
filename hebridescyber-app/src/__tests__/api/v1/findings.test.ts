import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, respondMock } = vi.hoisted(() => ({ authenticateApiRequestMock: vi.fn(), respondMock: vi.fn() }));

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authenticateApiRequestMock, supabaseAdmin: {} }));
vi.mock("@/pages/api/findings", () => ({ respondWithFindings: respondMock }));

import handler from "@/pages/api/v1/findings";

function call(method: RequestMethod = "GET", query: Record<string, string> = {}) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, query });
  return handler(req, res).then(() => ({ req, res }));
}

describe("GET /api/v1/findings", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "o1", via: "api_key" });
    respondMock.mockReset().mockImplementation((_req: NextApiRequest, res: NextApiResponse) => res.status(200).json({ ok: true }));
  });

  it("requires GET and an API key or session", async () => {
    expect((await call("POST")).res._getStatusCode()).toBe(405);
    authenticateApiRequestMock.mockResolvedValue(null);
    const { res } = await call();
    expect(res._getStatusCode()).toBe(401);
    expect((res._getJSONData() as { error: string }).error).toContain("Authorization: Bearer");
    expect(respondMock).not.toHaveBeenCalled();
  });

  it("serves the same list as /api/findings for the caller's own account, query and all", async () => {
    const { req, res } = await call("GET", { sort: "priority" });
    expect(res._getStatusCode()).toBe(200);
    expect(respondMock).toHaveBeenCalledWith(req, res, "o1");
    expect(req.query).toEqual({ sort: "priority" });
  });
});

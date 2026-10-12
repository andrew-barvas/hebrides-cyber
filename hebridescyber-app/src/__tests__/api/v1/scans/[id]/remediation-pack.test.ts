import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock } = vi.hoisted(() => ({ authenticateApiRequestMock: vi.fn() }));

// Same table-keyed chainable stub as compliance.test.ts/export.test.ts.
function makeQueryBuilder(result: unknown) {
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    order: () => builder,
    limit: () => builder,
    maybeSingle: () => Promise.resolve(result),
  };
  return builder;
}

let supabaseTables: Record<string, unknown> = {};

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: {
    from: (table: string) => makeQueryBuilder(supabaseTables[table]),
  },
}));

import handler from "@/pages/api/v1/scans/[id]/remediation-pack";

function mockReqRes(query: Record<string, string>) {
  return createMocks<NextApiRequest, NextApiResponse>({
    method: "GET",
    query,
    headers: { authorization: "Bearer test-token" },
  });
}

function ownScanWithFindings(findings: unknown[], score: number | null = null) {
  authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
  supabaseTables.scans = { data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com" } };
  supabaseTables.scan_results = { data: { score, results: { findings } } };
}

describe("GET /api/v1/scans/[id]/remediation-pack", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset();
    supabaseTables = {};
  });

  it("rejects non-GET methods with 405", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "POST" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 401 when the caller is not authenticated", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    const { req, res } = mockReqRes({ id: "scan-1" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 404 for a missing scan and 403 for someone else's", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    supabaseTables.scans = { data: null };
    let { req, res } = mockReqRes({ id: "missing" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);

    supabaseTables.scans = { data: { id: "scan-1", owner: "someone-else", target_url: "https://example.com" } };
    ({ req, res } = mockReqRes({ id: "scan-1" }));
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 404 when the scan has no results yet", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    supabaseTables.scans = { data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com" } };
    supabaseTables.scan_results = { data: null };
    const { req, res } = mockReqRes({ id: "scan-1" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);
  });

  it("returns the pack as a Markdown attachment", async () => {
    ownScanWithFindings([{ severity: "high", title: "Missing CSP", detail: "d", checkId: "headers.csp" }], 61);
    const { req, res } = mockReqRes({ id: "scan-1" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Content-Type")).toBe("text/markdown; charset=utf-8");
    expect(res.getHeader("Content-Disposition")).toContain("example.com-remediation-pack.md");
    const body = res._getData() as string;
    expect(body).toContain("## Headers");
    expect(body).toContain("Missing CSP");
    expect(body).toContain("**Score at time of scan:** 61/100");
  });

  it("a scan with no actionable findings still 200s with the 'nothing to fix' message", async () => {
    ownScanWithFindings([{ severity: "info", title: "FYI only", detail: "d", checkId: "recon.subdomains-found" }]);
    const { req, res } = mockReqRes({ id: "scan-1" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(res._getData() as string).toContain("No actionable findings");
  });
});

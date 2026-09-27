import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock } = vi.hoisted(() => ({ authenticateApiRequestMock: vi.fn() }));

// Same table-keyed chainable stub as export.test.ts.
function makeQueryBuilder(result: unknown) {
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
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

import handler from "@/pages/api/v1/scans/[id]/compliance";
import { COMPLIANCE_REPORT_DISCLAIMER } from "@/lib/complianceReport";

function mockReqRes(query: Record<string, string>) {
  return createMocks<NextApiRequest, NextApiResponse>({
    method: "GET",
    query,
    headers: { authorization: "Bearer test-token" },
  });
}

function ownScanWithFindings(findings: unknown[]) {
  authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
  supabaseTables.scans = { data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com" } };
  supabaseTables.scan_results = { data: { results: { findings } } };
}

describe("GET /api/v1/scans/[id]/compliance", () => {
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

  it("rejects an unknown format before touching the database", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    const { req, res } = mockReqRes({ id: "scan-1", format: "pdf" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
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

  it("defaults to a Markdown report with the disclaimer", async () => {
    ownScanWithFindings([]);
    const { req, res } = mockReqRes({ id: "scan-1" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Content-Type")).toBe("text/markdown; charset=utf-8");
    expect(res.getHeader("Content-Disposition")).toContain("example.com-compliance.md");
    expect(res._getData()).toContain(COMPLIANCE_REPORT_DISCLAIMER);
  });

  it("returns CSV when format=csv", async () => {
    ownScanWithFindings([]);
    const { req, res } = mockReqRes({ id: "scan-1", format: "CSV" });
    await handler(req, res);
    expect(res.getHeader("Content-Type")).toBe("text/csv; charset=utf-8");
    expect(res.getHeader("Content-Disposition")).toContain("example.com-compliance.csv");
    expect((res._getData() as string).split("\r\n")[2]).toBe("framework,control,result,finding_count,findings");
  });

  // Findings stored before per-finding compliance refs existed have none;
  // the route derives them from checkId so an old scan's report isn't blank.
  it("maps legacy findings without stored refs via their checkId", async () => {
    ownScanWithFindings([{ severity: "high", title: "No HTTPS", detail: "d", checkId: "tls.no-https" }]);
    const { req, res } = mockReqRes({ id: "scan-1", format: "json" });
    await handler(req, res);
    const body = res._getJSONData() as {
      disclaimer: string;
      frameworks: { framework: string; controls: { result: string; findings: { checkId: string }[] }[] }[];
    };
    expect(body.disclaimer).toBe(COMPLIANCE_REPORT_DISCLAIMER);
    const ce = body.frameworks.find((fw) => fw.framework === "cyber-essentials")!;
    const hit = ce.controls.find((c) => c.findings.some((f) => f.checkId === "tls.no-https"));
    expect(hit?.result).toBe("high_severity_issues_found");
  });
});

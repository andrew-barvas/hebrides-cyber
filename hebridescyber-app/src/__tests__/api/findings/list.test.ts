import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import type { FindingRow } from "@/lib/findingsView";

const { authenticateApiRequestMock, loadMock } = vi.hoisted(() => ({ authenticateApiRequestMock: vi.fn(), loadMock: vi.fn() }));

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authenticateApiRequestMock, supabaseAdmin: { tag: "admin" } }));
vi.mock("@/lib/findingsView", async (importOriginal) => ({ ...(await importOriginal<typeof import("@/lib/findingsView")>()), loadFindingsView: loadMock }));

import handler from "@/pages/api/findings/index";

function call(method: RequestMethod = "GET", query: Record<string, string> = {}) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, query });
  return handler(req, res).then(() => res);
}

type Body = {
  groups: Array<{ key: string; siteCount?: number; count?: number }>;
  items: Array<{ host: string }>;
  facets: { sites: unknown[] };
};

const row = (over: Partial<FindingRow> = {}): FindingRow => ({
  key: "a.example headers.hsts", host: "a.example", checkId: "headers.hsts", checkBase: "headers.hsts", category: "headers",
  severity: "medium", title: "Missing HSTS", detail: null, firstSeenAt: "2026-09-01T00:00:00Z", ageDays: 30, slaState: null, slaDueAt: null,
  knownExploited: false, ransomware: false, epss: null, cveIds: [], scanId: "s1", triage: null, ...over,
});

const rows = [
  row(),
  row({ key: "b.example headers.hsts", host: "b.example" }),
  row({ key: "b.example =x", host: "b.example", checkId: "dns.spf", checkBase: "dns.spf", category: "dns", title: "=cmd()", severity: "high" }),
];

describe("GET /api/findings", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "o1", via: "session" });
    loadMock.mockReset().mockResolvedValue({
      ok: true,
      data: { available: true, triageAvailable: true, slaEnabled: false, detailComplete: true, truncated: false, rows },
    });
  });

  it("requires authentication and GET", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    expect((await call())._getStatusCode()).toBe(401);
    expect((await call("POST"))._getStatusCode()).toBe(405);
    expect(loadMock).not.toHaveBeenCalled();
  });

  it("loads only the caller's own account", async () => {
    await call();
    expect(loadMock).toHaveBeenCalledWith({ tag: "admin" }, "o1");
  });

  it("returns groups by default, most severe first", async () => {
    const res = await call();
    const body = res._getJSONData() as Body;
    expect(res._getStatusCode()).toBe(200);
    expect(body).toMatchObject({ available: true, view: "grouped", totalFindings: 3, total: 2, page: 1, pageCount: 1, items: [] });
    expect(body.groups.map((g: { key: string }) => g.key)).toEqual(["dns.spf", "headers.hsts"]);
    expect(body.groups[1]).toMatchObject({ siteCount: 2, count: 2 });
    expect(body.facets.sites).toHaveLength(2);
  });

  it("returns paginated rows and applies filters", async () => {
    const res = await call("GET", { view: "rows", site: "b.example", pageSize: "1", page: "2" });
    const body = res._getJSONData() as Body;
    expect(body).toMatchObject({ view: "rows", totalFindings: 2, total: 2, page: 2, pageSize: 1, pageCount: 2, groups: [] });
    expect(body.items).toHaveLength(1);
    expect(body.items[0].host).toBe("b.example");
  });

  it("exports the filtered list as CSV with formula-safe cells", async () => {
    const res = await call("GET", { format: "csv", severity: "high" });
    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Content-Type")).toBe("text/csv; charset=utf-8");
    expect(res.getHeader("Content-Disposition")).toContain("open-findings.csv");
    const lines = res._getData().split("\r\n");
    expect(lines).toHaveLength(3);
    expect(lines[1]).toContain("'=cmd()");
  });

  it("passes through an unavailable table", async () => {
    loadMock.mockResolvedValue({ ok: true, data: { available: false, triageAvailable: false, slaEnabled: false, detailComplete: true, truncated: false, rows: [] } });
    const body = (await call())._getJSONData();
    expect(body).toMatchObject({ available: false, totalFindings: 0, groups: [] });
  });

  it("500s when the data can't be loaded", async () => {
    loadMock.mockResolvedValue({ ok: false, error: "Could not load findings" });
    const res = await call();
    expect(res._getStatusCode()).toBe(500);
    expect(res._getJSONData()).toEqual({ error: "Could not load findings" });
  });
});

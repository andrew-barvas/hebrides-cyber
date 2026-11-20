import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, loadMock, galleryMock, pdfMock, rateMock, adminMock } = vi.hoisted(() => ({
  authMock: vi.fn(),
  loadMock: vi.fn(),
  galleryMock: vi.fn(),
  pdfMock: vi.fn(),
  rateMock: vi.fn(),
  adminMock: vi.fn(),
}));

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authMock, supabaseAdmin: { tag: "admin" } }));
vi.mock("@/lib/adminAuth", () => ({ requireAdmin: adminMock, supabaseAdmin: { tag: "admin" } }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: rateMock }));
vi.mock("@/lib/reportPdf", () => ({ htmlToPdf: pdfMock }));
vi.mock("@/lib/lookoutLookalikes", () => ({ loadReportLookalikes: async () => ({ available: false, newInPeriod: [], totalKnown: 0 }) }));
vi.mock("@/lib/lookoutBreaches", () => ({ loadReportBreaches: async () => ({ available: false, sites: [] }) }));
vi.mock("@/lib/reportTrends", async (orig) => ({ ...(await orig<typeof import("@/lib/reportTrends")>()), loadReportTrends: async () => ({ available: true, sites: [{ host: "a.example", start: 50, end: 70, change: 20 }], average: [{ at: "2026-11-01", score: 50 }, { at: "2026-11-19", score: 70 }] }) }));
vi.mock("@/lib/lookoutReportPdf", async (orig) => ({ ...(await orig<typeof import("@/lib/lookoutReportPdf")>()), loadReportForPdf: loadMock, loadEstateGallery: galleryMock }));

import customer from "@/pages/api/lookout/report-pdf";
import admin from "@/pages/api/admin/lookout/report-pdf";

const ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const report = (status: string) => ({
  customer: "c1",
  report: { period_start: "2026-10-20", period_end: "2026-11-19", status, summary: "s", published_at: null, acknowledged_at: null },
  items: [],
});

async function call(handler: typeof customer, query: Record<string, string>) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query });
  await handler(req, res);
  return res;
}

describe("Lookout report PDF: the less common paths", () => {
  beforeEach(() => {
    authMock.mockReset().mockResolvedValue({ ownerId: "c1", via: "session" });
    adminMock.mockReset().mockResolvedValue("admin-1");
    loadMock.mockReset().mockResolvedValue(report("published"));
    galleryMock.mockReset().mockResolvedValue([]);
    pdfMock.mockReset().mockResolvedValue(Buffer.from("%PDF"));
    rateMock.mockReset().mockResolvedValue({ allowed: true });
  });

  it("returns the HTML, trend included, for both routes when asked", async () => {
    for (const handler of [customer, admin]) {
      const res = await call(handler, { id: ID, format: "html" });
      expect(res._getStatusCode()).toBe(200);
      expect(res.getHeader("Content-Type")).toBe("text/html; charset=utf-8");
      expect(res._getData()).toContain("Your security score over this period");
    }
  });

  it("answers 500 when the report can't be read or the PDF can't be rendered", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    loadMock.mockRejectedValue(new Error("db down"));
    expect((await call(customer, { id: ID }))._getStatusCode()).toBe(500);
    expect((await call(admin, { id: ID }))._getStatusCode()).toBe(500);
    loadMock.mockResolvedValue(report("published"));
    pdfMock.mockRejectedValue(new Error("chromium missing"));
    expect((await call(customer, { id: ID }))._getStatusCode()).toBe(500);
    expect((await call(admin, { id: ID }))._getStatusCode()).toBe(500);
    spy.mockRestore();
  });

  it("refuses other methods, the unauthenticated, and unknown reports", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "POST", query: { id: ID } });
    await customer(req, res);
    expect(res._getStatusCode()).toBe(405);
    const post = createMocks<NextApiRequest, NextApiResponse>({ method: "POST", query: { id: ID } });
    await admin(post.req, post.res);
    expect(post.res._getStatusCode()).toBe(405);
    authMock.mockResolvedValueOnce(null);
    expect((await call(customer, { id: ID }))._getStatusCode()).toBe(401);
    loadMock.mockResolvedValue(null);
    expect((await call(admin, { id: ID }))._getStatusCode()).toBe(404);
  });

  it("names an admin's draft preview as a draft", async () => {
    loadMock.mockResolvedValue(report("draft"));
    const res = await call(admin, { id: ID });
    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Content-Disposition")).toBe('attachment; filename="draft-lookout-report-2026-11-19.pdf"');
    loadMock.mockResolvedValue(report("published"));
    expect((await call(admin, { id: ID })).getHeader("Content-Disposition")).toBe('attachment; filename="lookout-report-2026-11-19.pdf"');
  });
});

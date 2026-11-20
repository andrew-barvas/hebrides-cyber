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

describe("Lookout report PDF", () => {
  beforeEach(() => {
    authMock.mockReset().mockResolvedValue({ ownerId: "c1", via: "session" });
    adminMock.mockReset().mockResolvedValue("admin-1");
    loadMock.mockReset().mockResolvedValue(report("published"));
    galleryMock.mockReset().mockResolvedValue([]);
    pdfMock.mockReset().mockResolvedValue(Buffer.from("%PDF"));
    rateMock.mockReset().mockResolvedValue({ allowed: true });
  });

  it("gives the customer their published report as a dated PDF", async () => {
    const res = await call(customer, { id: ID });
    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Content-Type")).toBe("application/pdf");
    expect(res.getHeader("Content-Disposition")).toBe('attachment; filename="lookout-report-2026-11-19.pdf"');
    expect(galleryMock).toHaveBeenCalledWith({ tag: "admin" }, "c1", "2026-11-19");
  });

  it("hides drafts, other customers' reports and malformed ids", async () => {
    loadMock.mockResolvedValue(report("draft"));
    expect((await call(customer, { id: ID }))._getStatusCode()).toBe(404);
    loadMock.mockResolvedValue({ ...report("published"), customer: "someone-else" });
    expect((await call(customer, { id: ID }))._getStatusCode()).toBe(404);
    expect((await call(customer, { id: "x" }))._getStatusCode()).toBe(404);
    expect(pdfMock).not.toHaveBeenCalled();
  });

  it("is rate-limited, since each call launches Chromium", async () => {
    rateMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 60 });
    const res = await call(customer, { id: ID });
    expect(res._getStatusCode()).toBe(429);
    expect(pdfMock).not.toHaveBeenCalled();
  });

  it("lets an admin preview a draft, marked as one, and nobody else", async () => {
    loadMock.mockResolvedValue(report("draft"));
    const res = await call(admin, { id: ID, format: "html" });
    expect(res._getStatusCode()).toBe(200);
    expect(res._getData()).toContain("DRAFT");
    adminMock.mockResolvedValue(null);
    expect((await call(admin, { id: ID }))._getStatusCode()).toBe(403);
  });
});

describe("admin Lookout report PDF failures", () => {
  beforeEach(() => {
    adminMock.mockReset().mockResolvedValue("admin-1");
    loadMock.mockReset().mockResolvedValue(report("published"));
    galleryMock.mockReset().mockResolvedValue([]);
    pdfMock.mockReset().mockResolvedValue(Buffer.from("%PDF"));
  });

  it("answers 405, 404 for no report, 500 on a read error and on a failed render", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "POST", query: { id: ID } });
    await admin(req, res);
    expect(res._getStatusCode()).toBe(405);
    loadMock.mockResolvedValueOnce(null);
    expect((await call(admin, { id: ID }))._getStatusCode()).toBe(404);
    loadMock.mockRejectedValueOnce(new Error("db"));
    expect((await call(admin, { id: ID }))._getStatusCode()).toBe(500);
    pdfMock.mockRejectedValueOnce(new Error("chromium"));
    const r = await call(admin, { id: ID });
    expect(r._getStatusCode()).toBe(500);
    expect(r._getData()).toContain("PDF render failed");
  });

  it("gives a draft PDF a draft file name", async () => {
    loadMock.mockResolvedValueOnce(report("draft"));
    const r = await call(admin, { id: ID });
    expect(r.getHeader("Content-Disposition")).toBe('attachment; filename="draft-lookout-report-2026-11-19.pdf"');
  });
});

describe("customer Lookout report PDF failures", () => {
  beforeEach(() => {
    authMock.mockReset().mockResolvedValue({ ownerId: "c1", via: "session" });
    loadMock.mockReset().mockResolvedValue(report("published"));
    galleryMock.mockReset().mockResolvedValue([]);
    pdfMock.mockReset().mockResolvedValue(Buffer.from("%PDF"));
    rateMock.mockReset().mockResolvedValue({ allowed: true });
  });

  it("answers 405, 401, the HTML preview, and 500s on read or render failure", async () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "POST", query: { id: ID } });
    await customer(req, res);
    expect(res._getStatusCode()).toBe(405);
    authMock.mockResolvedValueOnce(null);
    expect((await call(customer, { id: ID }))._getStatusCode()).toBe(401);
    const html = await call(customer, { id: ID, format: "html" });
    expect(html.getHeader("Content-Type")).toContain("text/html");
    loadMock.mockRejectedValueOnce(new Error("db"));
    expect((await call(customer, { id: ID }))._getStatusCode()).toBe(500);
    pdfMock.mockRejectedValueOnce(new Error("chromium"));
    expect((await call(customer, { id: ID }))._getStatusCode()).toBe(500);
    err.mockRestore();
  });
});

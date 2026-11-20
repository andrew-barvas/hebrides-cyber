// Focused coverage added alongside E-12 (docs/ENHANCEMENTS.md): this route
// had no test file at all before its rate limit was added. It covers the
// auth/rate-limit gates, branding, and that the PDF is drawn without a browser:
// Playwright is mocked to fail the way it does on Azure Static Web Apps, where
// no Chromium exists (every download answered 500 until htmlPdf.ts).
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, checkRateLimitMock, renderMock, launchMock, pdfSpy, captureMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  checkRateLimitMock: vi.fn(),
  renderMock: vi.fn(() => "<html><head><title>Hebrides Cyber — www.example.com</title></head><body><h1>Hebrides Cyber</h1></body></html>"),
  launchMock: vi.fn(),
  pdfSpy: vi.fn(),
  captureMock: vi.fn(),
}));

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    order: () => builder,
    limit: () => builder,
    maybeSingle: next,
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: checkRateLimitMock }));
vi.mock("@/lib/executiveReport", () => ({ renderExecutiveReportHtml: renderMock }));
vi.mock("@/lib/findingTriage", () => ({ loadTriageIndexForTarget: async () => ({ index: null }) }));
vi.mock("playwright", () => ({ chromium: { launch: launchMock } }));
vi.mock("@sentry/nextjs", () => ({ captureMessage: captureMock }));
vi.mock("@/lib/htmlPdf", async (orig) => {
  const real = await orig<typeof import("@/lib/htmlPdf")>();
  pdfSpy.mockImplementation(real.renderHtmlPdf);
  return { ...real, renderHtmlPdf: pdfSpy };
});

import handler from "@/pages/api/generate-report";

function mockReqRes(query: Record<string, string> = { scan_id: "scan-1" }) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query });
}

describe("GET /api/generate-report", () => {
  beforeEach(() => {
    queues = {};
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
    checkRateLimitMock.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
    launchMock.mockReset().mockRejectedValue(new Error("browserType.launch: Executable doesn't exist at /home/.cache/ms-playwright/chromium"));
    captureMock.mockReset();
  });

  it("returns 405 for non-GET", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "POST" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 401 when unauthenticated", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 429 when the caller is rate-limited, before ever querying the scan", async () => {
    checkRateLimitMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 55 });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(429);
    expect(res._getHeaders()["retry-after"]).toBe("55");
    expect(queues.scan_results).toBeUndefined();
  });

  it("returns 400 when scan_id is missing", async () => {
    const { req, res } = mockReqRes({});
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  describe("the PDF", () => {
    const scanRow = { data: { scan_id: "scan-1", score: 80, results: { findings: [] }, scans: { owner: "owner-1", target_url: "https://www.example.com/", created_at: "2026-10-01T00:00:00Z" } }, error: null };

    it("is drawn without Chromium, which Azure Static Web Apps doesn't have", async () => {
      queues.scan_results = [scanRow];
      const { req, res } = mockReqRes();
      await handler(req, res);
      expect(res._getStatusCode()).toBe(200);
      expect(res.getHeader("Content-Type")).toBe("application/pdf");
      expect(res.getHeader("Content-Disposition")).toBe('attachment; filename="hebridescyber-report-scan-1.pdf"');
      const { PDFDocument } = await import("pdf-lib");
      const doc = await PDFDocument.load(new Uint8Array(res._getData() as Buffer));
      expect(doc.getTitle()).toBe("Hebrides Cyber — www.example.com");
      expect(launchMock).not.toHaveBeenCalled();
    });

    it("answers a fixed message, and reports to Sentry, when drawing fails", async () => {
      queues.scan_results = [scanRow];
      pdfSpy.mockRejectedValueOnce(new Error("internal layout detail"));
      const { req, res } = mockReqRes();
      await handler(req, res);
      expect(res._getStatusCode()).toBe(500);
      expect(res._getData()).not.toContain("internal layout detail");
      expect(captureMock).toHaveBeenCalledWith(expect.stringContaining("generate-report"), expect.anything());
    });
  });

  describe("white-label branding", () => {
    const scanRow = { data: { scan_id: "scan-1", score: 80, results: { findings: [] }, scans: { owner: "owner-1", target_url: "https://www.example.com/", created_at: "2026-10-01T00:00:00Z" } }, error: null };
    const brand = { brand_name: "Acme Security", brand_logo_url: "https://blob.example/logo.png" };

    beforeEach(() => {
      renderMock.mockClear();
    });

    it("brands the report for an active Agency owner", async () => {
      queues.scan_results = [scanRow];
      queues.subscriptions = [{ data: { plan: "agency", status: "active", ...brand }, error: null }];
      const { req, res } = mockReqRes();
      await handler(req, res);
      expect(res._getStatusCode()).toBe(200);
      expect(renderMock).toHaveBeenCalledWith(expect.objectContaining({ branding: { name: "Acme Security", logoUrl: "https://blob.example/logo.png" } }));
    });

    it.each(["cancelled", "past_due"])("drops the branding once the Agency subscription is %s", async (status) => {
      queues.scan_results = [scanRow];
      queues.subscriptions = [{ data: { plan: "agency", status, ...brand }, error: null }];
      const { req, res } = mockReqRes();
      await handler(req, res);
      expect(res._getStatusCode()).toBe(200);
      expect(renderMock).toHaveBeenCalledWith(expect.objectContaining({ branding: undefined }));
    });
  });
});

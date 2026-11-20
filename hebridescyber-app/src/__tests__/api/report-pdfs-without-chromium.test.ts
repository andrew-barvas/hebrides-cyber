// The site's PDF downloads, drawn without a browser. API routes run as Azure
// Static Web Apps managed Functions, which have no Chromium: every PDF route
// that printed with Playwright answered 500 there. Playwright is mocked to
// fail exactly as it does on SWA, and the PDFs must still come back.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { PDFDocument } from "pdf-lib";

const { authMock, adminMock, loadMock, galleryMock, rateMock, launchMock } = vi.hoisted(() => ({
  authMock: vi.fn(),
  adminMock: vi.fn(),
  loadMock: vi.fn(),
  galleryMock: vi.fn(),
  rateMock: vi.fn(),
  launchMock: vi.fn(),
}));

vi.mock("playwright", () => ({ chromium: { launch: launchMock } }));
vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authMock, supabaseAdmin: { tag: "admin" } }));
vi.mock("@/lib/adminAuth", () => ({ requireAdmin: adminMock, supabaseAdmin: { tag: "admin" } }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: rateMock }));
vi.mock("@/lib/lookoutLookalikes", () => ({ loadReportLookalikes: async () => ({ available: false, newInPeriod: [], totalKnown: 0 }) }));
vi.mock("@/lib/lookoutBreaches", () => ({ loadReportBreaches: async () => ({ available: false, sites: [] }) }));
vi.mock("@/lib/reportTrends", async (orig) => ({
  ...(await orig<typeof import("@/lib/reportTrends")>()),
  loadReportTrends: async () => ({ available: true, sites: [{ host: "www.example.com", start: 50, end: 80, change: 30 }], average: [{ at: "2026-10-27", score: 50 }, { at: "2026-11-19", score: 80 }] }),
}));
vi.mock("@/lib/lookoutReportPdf", async (orig) => ({ ...(await orig<typeof import("@/lib/lookoutReportPdf")>()), loadReportForPdf: loadMock, loadEstateGallery: galleryMock }));

import customer from "@/pages/api/lookout/report-pdf";
import admin from "@/pages/api/admin/lookout/report-pdf";

// A real 8x5 JPEG, as the estate gallery stores screenshots.
const JPEG =
  "data:image/jpeg;base64,/9j/2wBDABQODxIPDRQSEBIXFRQYHjIhHhwcHj0sLiQySUBMS0dARkVQWnNiUFVtVkVGZIhlbXd7gYKBTmCNl4x9lnN+gXz/2wBDARUXFx4aHjshITt8U0ZTfHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHz/wAARCAAFAAgDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAX/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFAEBAAAAAAAAAAAAAAAAAAAABP/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/AJYBoT//2Q==";
const ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const loaded = (status: string) => ({
  customer: "c1",
  report: { period_start: "2026-10-20", period_end: "2026-11-19", status, summary: "One new issue.\n\nTwo were fixed.", published_at: "2026-11-19T10:00:00Z", acknowledged_at: null },
  items: [{ host: "www.example.com", severity: "high", title: "Certificate expired 🚀", priority: 1, analyst_note: "Renew it", business_impact: "Visitors see a warning", fix_owner: "it_supplier" }],
});

async function call(handler: typeof customer, query: Record<string, string>) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query });
  await handler(req, res);
  return res;
}

async function pdfOf(res: Awaited<ReturnType<typeof call>>) {
  const bytes = res._getData() as Buffer;
  expect(bytes.subarray(0, 5).toString("latin1")).toBe("%PDF-");
  return { doc: await PDFDocument.load(new Uint8Array(bytes)), text: bytes.toString("latin1") };
}

describe("PDF downloads without Chromium", () => {
  beforeEach(() => {
    authMock.mockReset().mockResolvedValue({ ownerId: "c1", via: "session" });
    adminMock.mockReset().mockResolvedValue("admin-1");
    loadMock.mockReset().mockResolvedValue(loaded("published"));
    galleryMock.mockReset().mockResolvedValue([{ host: "www.example.com", dataUri: JPEG }]);
    rateMock.mockReset().mockResolvedValue({ allowed: true });
    launchMock.mockReset().mockRejectedValue(new Error("browserType.launch: Executable doesn't exist at /home/.cache/ms-playwright/chromium"));
  });

  it("gives the customer their Lookout report, gallery screenshot included", async () => {
    const res = await call(customer, { id: ID });
    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Content-Disposition")).toBe('attachment; filename="lookout-report-2026-11-19.pdf"');
    const { doc, text } = await pdfOf(res);
    expect(doc.getTitle()).toBe("Hebrides Cyber Lookout report 2026-10-20 to 2026-11-19");
    expect(text).toContain("/Subtype /Image");
    expect(launchMock).not.toHaveBeenCalled();
  });

  it("gives an admin the draft preview", async () => {
    loadMock.mockResolvedValue(loaded("draft"));
    const res = await call(admin, { id: ID });
    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Content-Disposition")).toBe('attachment; filename="draft-lookout-report-2026-11-19.pdf"');
    await pdfOf(res);
    expect(launchMock).not.toHaveBeenCalled();
  });
});

describe("API routes and Chromium", () => {
  it("no API route imports the Chromium renderer (reportPdf.ts)", () => {
    const root = path.resolve(__dirname, "../../pages/api");
    const offenders: string[] = [];
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const full = path.join(dir, name);
        if (statSync(full).isDirectory()) walk(full);
        else if (/\.(ts|tsx|js)$/.test(name) && /lib\/reportPdf["']|from ["']playwright["']/.test(readFileSync(full, "utf8"))) offenders.push(path.relative(root, full));
      }
    };
    walk(root);
    expect(offenders).toEqual([]);
  });
});

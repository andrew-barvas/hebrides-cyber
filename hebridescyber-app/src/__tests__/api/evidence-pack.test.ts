import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authMock, gateMock, rateMock, loadMock, pdfMock } = vi.hoisted(() => ({
  authMock: vi.fn(),
  gateMock: vi.fn(),
  rateMock: vi.fn(),
  loadMock: vi.fn(),
  pdfMock: vi.fn(),
}));

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authMock, supabaseAdmin: { tag: "admin" } }));
vi.mock("@/lib/planAccess", () => ({ planGate: gateMock }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: rateMock }));
vi.mock("@/lib/reportPdf", () => ({ htmlToPdf: pdfMock }));
vi.mock("@/lib/evidencePack", async (orig) => ({ ...(await orig<typeof import("@/lib/evidencePack")>()), loadEvidencePack: loadMock }));

import handler from "@/pages/api/account/evidence-pack";

const pack = {
  company: "Acme",
  generatedAt: "2026-11-20T10:00:00Z",
  sites: [],
  ce: { overall_status: "partial", score: 40, answered: 0, total_questions: 13, controls: [], recommendation: "" },
  insurance: [],
  fixFirst: [],
};

async function call(query: Record<string, string> = {}) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query });
  await handler(req, res);
  return res;
}

describe("GET /api/account/evidence-pack", () => {
  beforeEach(() => {
    authMock.mockReset().mockResolvedValue({ ownerId: "o1", via: "session" });
    gateMock.mockReset().mockResolvedValue("allowed");
    rateMock.mockReset().mockResolvedValue({ allowed: true });
    loadMock.mockReset().mockResolvedValue(pack);
    pdfMock.mockReset().mockResolvedValue(Buffer.from("%PDF"));
  });

  it("gives a Pro customer their pack as a dated PDF, for their own account", async () => {
    const res = await call();
    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Content-Disposition")).toBe('attachment; filename="security-evidence-pack-2026-11-20.pdf"');
    expect(gateMock).toHaveBeenCalledWith({ tag: "admin" }, "o1", "pro");
    expect(loadMock).toHaveBeenCalledWith({ tag: "admin" }, "o1");
  });

  it("refuses below Pro with a plan code, and needs a caller", async () => {
    gateMock.mockResolvedValue("denied");
    const res = await call();
    expect(res._getStatusCode()).toBe(403);
    expect(JSON.parse(res._getData()).code).toBe("plan_required");
    authMock.mockResolvedValue(null);
    expect((await call())._getStatusCode()).toBe(401);
    expect(loadMock).not.toHaveBeenCalled();
  });

  it("is rate-limited, and serves HTML on request", async () => {
    rateMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 60 });
    expect((await call())._getStatusCode()).toBe(429);
    rateMock.mockResolvedValue({ allowed: true });
    const html = await call({ format: "html" });
    expect(html._getData()).toContain("Security evidence pack");
    expect(pdfMock).not.toHaveBeenCalled();
  });

  it("answers a fixed message when building fails", async () => {
    loadMock.mockRejectedValue(new Error('relation "scans" does not exist'));
    const res = await call();
    expect(res._getStatusCode()).toBe(500);
    expect(res._getData()).not.toContain("relation");
  });
});

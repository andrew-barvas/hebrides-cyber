import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { PDFDocument } from "pdf-lib";
import type { FindingRow } from "@/lib/findingsView";

const { authMock, gateMock, rateMock, loadMock, launchMock, captureMock } = vi.hoisted(() => ({
  authMock: vi.fn(),
  gateMock: vi.fn(),
  rateMock: vi.fn(),
  loadMock: vi.fn(),
  launchMock: vi.fn(),
  captureMock: vi.fn(),
}));

vi.mock("@/lib/apiAuth", () => ({ authenticateApiRequest: authMock, supabaseAdmin: { tag: "admin" } }));
vi.mock("@/lib/planAccess", () => ({ planGate: gateMock }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: rateMock }));
vi.mock("@sentry/nextjs", () => ({ captureMessage: captureMock }));
// Production: Azure Static Web Apps managed Functions have no Chromium, so
// Playwright fails exactly like this. The pack must not depend on it.
vi.mock("playwright", () => ({ chromium: { launch: launchMock } }));
vi.mock("@/lib/evidencePack", async (orig) => ({ ...(await orig<typeof import("@/lib/evidencePack")>()), loadEvidencePack: loadMock }));

import handler from "@/pages/api/account/evidence-pack";
import { ceReadinessFromRows, insuranceAnswers, type EvidencePack } from "@/lib/evidencePack";

// The state the customer was in on production: a completed scan with open
// findings, and none of the 13 Cyber Essentials questions answered yet.
const rows = [
  { key: "example.co.uk headers.hsts-missing", host: "example.co.uk", checkId: "headers.hsts-missing", checkBase: "headers.hsts-missing", category: "headers", severity: "medium", title: "HSTS header missing — “Strict-Transport-Security” → not set", detail: "No HSTS.\nSee ≥ RFC 6797 ✓", firstSeenAt: "2026-11-19T09:00:00Z", ageDays: 1 },
] as unknown as FindingRow[];
const sites = [{ host: "example.co.uk", lastScanAt: "2026-11-19T09:00:00Z" }];
const pack: EvidencePack = {
  company: "Acme Ltd — Łódź 🚀",
  generatedAt: "2026-11-20T10:00:00Z",
  sites,
  ce: ceReadinessFromRows(rows, []),
  insurance: insuranceAnswers({ rows, scannedSites: sites, m365Checked: null, workspaceChecked: null, answers: [] }),
  fixFirst: rows.map((r) => ({ ...r, priority: { score: 5, reasons: [] } })) as unknown as EvidencePack["fixFirst"],
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
    launchMock.mockReset().mockRejectedValue(new Error("browserType.launch: Executable doesn't exist at /home/.cache/ms-playwright/chromium"));
    captureMock.mockReset();
  });

  it("downloads the pack with no questions answered yet and a completed scan, without Chromium", async () => {
    expect(pack.ce.answered).toBe(0);
    const res = await call();
    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Content-Type")).toBe("application/pdf");
    expect(res.getHeader("Content-Disposition")).toBe('attachment; filename="security-evidence-pack-2026-11-20.pdf"');
    const bytes = res._getData() as Buffer;
    expect(bytes.subarray(0, 5).toString("latin1")).toBe("%PDF-");
    const doc = await PDFDocument.load(new Uint8Array(bytes));
    expect(doc.getTitle()).toBe("Security evidence pack 2026-11-20");
    expect(doc.getPageCount()).toBeGreaterThanOrEqual(1);
    expect(launchMock).not.toHaveBeenCalled();
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
    expect(html._getData()).toContain("Not answered yet");
  });

  it("answers a fixed message, and reports to Sentry, when building fails", async () => {
    loadMock.mockRejectedValue(new Error('relation "scans" does not exist'));
    const res = await call();
    expect(res._getStatusCode()).toBe(500);
    expect(res._getData()).not.toContain("relation");
    expect(captureMock).toHaveBeenCalledWith(expect.stringContaining("account/evidence-pack"), expect.anything());
  });

  it("answers a fixed message, and reports to Sentry, when the plan check fails", async () => {
    gateMock.mockResolvedValue("error");
    const res = await call();
    expect(res._getStatusCode()).toBe(500);
    expect(JSON.parse(res._getData()).error).toBe("Could not check your plan. Try again.");
    expect(captureMock).toHaveBeenCalled();
    expect(loadMock).not.toHaveBeenCalled();
  });
});

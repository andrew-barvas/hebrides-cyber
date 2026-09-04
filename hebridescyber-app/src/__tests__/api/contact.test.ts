import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { checkRateLimitMock, insertMock, sendEmailMock } = vi.hoisted(() => ({
  checkRateLimitMock: vi.fn(),
  insertMock: vi.fn(),
  sendEmailMock: vi.fn(),
}));

vi.mock("@/lib/rateLimit", () => ({
  checkRateLimit: checkRateLimitMock,
  getClientIp: () => "203.0.113.7",
}));

vi.mock("@/lib/supabaseAdmin", () => ({
  supabaseAdmin: { from: () => ({ insert: insertMock }) },
}));

vi.mock("@/lib/email", () => ({
  sendEmail: sendEmailMock,
  escapeHtml: (s: string) => s,
}));

import handler from "@/pages/api/contact";

function mockReqRes(body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "POST", body });
}

const validBody = { name: "Jo Smith", email: "jo@example.com", message: "Please quote a site audit." };

describe("POST /api/contact", () => {
  beforeEach(() => {
    checkRateLimitMock.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
    insertMock.mockReset().mockResolvedValue({ error: null });
    sendEmailMock.mockReset().mockResolvedValue({ ok: true });
  });

  it("rejects non-POST methods with 405", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("rate-limits by client IP before touching the database", async () => {
    checkRateLimitMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 120 });
    const { req, res } = mockReqRes(validBody);
    await handler(req, res);

    expect(res._getStatusCode()).toBe(429);
    expect(res._getHeaders()["retry-after"]).toBe("120");
    expect(checkRateLimitMock).toHaveBeenCalledWith("203.0.113.7", "contact");
    expect(insertMock).not.toHaveBeenCalled();
  });

  it("rejects a missing/short name", async () => {
    const { req, res } = mockReqRes({ ...validBody, name: "A" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("rejects an invalid email", async () => {
    const { req, res } = mockReqRes({ ...validBody, email: "not-an-email" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("rejects a too-short message", async () => {
    const { req, res } = mockReqRes({ ...validBody, message: "hi" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("rejects an invalid optional url", async () => {
    const { req, res } = mockReqRes({ ...validBody, url: "not a url" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("saves the enquiry and sends a notification email on valid input", async () => {
    const { req, res } = mockReqRes(validBody);
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(insertMock).toHaveBeenCalledWith(
      expect.objectContaining({ name: "Jo Smith", email: "jo@example.com" }),
    );
    expect(sendEmailMock).toHaveBeenCalled();
  });

  it("returns 500 if the database insert fails, without sending an email", async () => {
    insertMock.mockResolvedValue({ error: { message: "db down" } });
    const { req, res } = mockReqRes(validBody);
    await handler(req, res);

    expect(res._getStatusCode()).toBe(500);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("still returns 200 if the notification email fails to send (non-fatal)", async () => {
    sendEmailMock.mockResolvedValue({ ok: false, error: "resend down" });
    const { req, res } = mockReqRes(validBody);
    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
  });
});

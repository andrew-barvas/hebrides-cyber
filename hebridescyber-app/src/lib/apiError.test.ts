import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const captureMessage = vi.fn();
vi.mock("@sentry/nextjs", () => ({ captureMessage: (...args: unknown[]) => captureMessage(...args) }));

import { respondInternalError, INTERNAL_ERROR_MESSAGE } from "./apiError";

function mockRes() {
  return createMocks<NextApiRequest, NextApiResponse>().res;
}

describe("respondInternalError", () => {
  beforeEach(() => {
    captureMessage.mockReset();
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  const dbError = { code: "23514", message: 'new row for relation "scans" violates check constraint "scans_status_check"' };

  it("answers 500 with a generic message that leaks nothing from the error", () => {
    const res = mockRes();
    respondInternalError(res, "run-scan", dbError);
    expect(res._getStatusCode()).toBe(500);
    expect(res._getJSONData()).toEqual({ error: INTERNAL_ERROR_MESSAGE });
    expect(JSON.stringify(res._getJSONData())).not.toContain("scans_status_check");
  });

  it("keeps the detail server-side: logged with the route and sent to Sentry", () => {
    respondInternalError(mockRes(), "run-scan", dbError);
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("[run-scan]"));
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("scans_status_check"));
    expect(captureMessage).toHaveBeenCalledWith(
      expect.stringContaining("scans_status_check"),
      expect.objectContaining({ level: "error", tags: { route: "run-scan", db_code: "23514" } })
    );
  });

  it("honours a status, public message and extra fields", () => {
    const res = mockRes();
    respondInternalError(res, "run-scan", dbError, { status: 404, publicMessage: "Scan not found", extra: { code: "queue_failed" } });
    expect(res._getStatusCode()).toBe(404);
    expect(res._getJSONData()).toEqual({ error: "Scan not found", code: "queue_failed" });
  });

  it("tolerates a null error", () => {
    const res = mockRes();
    respondInternalError(res, "x", null);
    expect(res._getStatusCode()).toBe(500);
    expect(console.error).toHaveBeenCalledWith("[x] unknown error");
  });
});

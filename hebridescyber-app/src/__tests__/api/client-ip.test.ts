import { describe, it, expect } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import handler from "@/pages/api/client-ip";

describe("GET /api/client-ip", () => {
  it("rejects non-GET methods with 405", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "POST" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns the caller's address and is never cached", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
      method: "GET",
      headers: { "x-forwarded-for": "203.0.113.7" },
    });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Cache-Control")).toBe("no-store");
    expect((res._getJSONData() as { ip: string }).ip).toBe("203.0.113.7");
  });

  it("is rate-limited per client IP", async () => {
    let last = 0;
    for (let i = 0; i < 121; i++) {
      const { req, res } = createMocks<NextApiRequest, NextApiResponse>({
        method: "GET",
        headers: { "x-forwarded-for": "198.51.100.44" },
      });
      await handler(req, res);
      last = res._getStatusCode();
    }
    expect(last).toBe(429);
  });
});

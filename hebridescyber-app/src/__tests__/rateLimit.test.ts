import { describe, it, expect } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest } from "next";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";

// No UPSTASH_REDIS_REST_URL/TOKEN is set in the test environment, so these
// exercise the in-memory fallback path — real enough to verify namespacing
// and the allow/deny boundary without mocking fetch.

describe("checkRateLimit", () => {
  it("allows requests under the limit", async () => {
    const result = await checkRateLimit("test-key-under-limit");
    expect(result.allowed).toBe(true);
  });

  it("blocks the 11th request within the window for the same key+namespace", async () => {
    const key = "test-key-over-limit";
    for (let i = 0; i < 10; i++) {
      await checkRateLimit(key, "test-ns-a");
    }
    const result = await checkRateLimit(key, "test-ns-a");
    expect(result.allowed).toBe(false);
    expect(result.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("keeps different namespaces isolated even for the same raw key", async () => {
    const key = "test-key-shared-raw-value";
    for (let i = 0; i < 10; i++) {
      await checkRateLimit(key, "test-ns-b");
    }
    // Same key, different namespace — should have its own fresh bucket,
    // not inherit test-ns-b's exhausted count.
    const result = await checkRateLimit(key, "test-ns-c");
    expect(result.allowed).toBe(true);
  });
});

describe("getClientIp", () => {
  function mockReq(headers: Record<string, string | string[]> = {}, remoteAddress?: string) {
    const { req } = createMocks<NextApiRequest>({ headers });
    if (remoteAddress) Object.defineProperty(req.socket, "remoteAddress", { value: remoteAddress });
    return req;
  }

  it("uses the first entry of x-forwarded-for when present", () => {
    const req = mockReq({ "x-forwarded-for": "203.0.113.7, 10.0.0.1, 10.0.0.2" });
    expect(getClientIp(req)).toBe("203.0.113.7");
  });

  it("handles x-forwarded-for arriving as an array", () => {
    const req = mockReq({ "x-forwarded-for": ["203.0.113.9", "10.0.0.1"] });
    expect(getClientIp(req)).toBe("203.0.113.9");
  });

  it("falls back to the socket address when no proxy header is present", () => {
    const req = mockReq({}, "127.0.0.1");
    expect(getClientIp(req)).toBe("127.0.0.1");
  });

  it("falls back to \"unknown\" when neither is available", () => {
    const req = mockReq({});
    expect(getClientIp(req)).toBe("unknown");
  });
});

import { describe, it, expect, vi, afterEach } from "vitest";
import type { NextApiRequest } from "next";
import { checkRateLimit, DEFAULT_RATE_LIMIT, getClientIp } from "./rateLimit";

// No UPSTASH_* env in the test environment, so these exercise the in-memory
// fallback. Each test uses its own key — the buckets are module state.

afterEach(() => {
  vi.useRealTimers();
});

async function drain(key: string, namespace: string, times: number, policy?: { max: number; windowSeconds: number }) {
  const results = [];
  for (let i = 0; i < times; i++) results.push(await checkRateLimit(key, namespace, policy));
  return results;
}

describe("checkRateLimit (in-memory)", () => {
  it("keeps the original 10-per-hour default for existing callers", async () => {
    expect(DEFAULT_RATE_LIMIT).toEqual({ max: 10, windowSeconds: 3600 });
    const results = await drain("owner-default", "run-scan", 11);
    expect(results.slice(0, 10).every((r) => r.allowed)).toBe(true);
    expect(results[10].allowed).toBe(false);
    expect(results[10].retryAfterSeconds).toBeGreaterThan(0);
    expect(results[10].retryAfterSeconds).toBeLessThanOrEqual(3600);
  });

  it("honours a per-namespace policy", async () => {
    const policy = { max: 3, windowSeconds: 60 };
    const results = await drain("ip-policy", "health", 4, policy);
    expect(results.map((r) => r.allowed)).toEqual([true, true, true, false]);
    expect(results[3].retryAfterSeconds).toBeLessThanOrEqual(60);
  });

  it("keeps namespaces separate for the same key", async () => {
    await drain("shared-key", "contact", 10);
    expect((await checkRateLimit("shared-key", "contact")).allowed).toBe(false);
    expect((await checkRateLimit("shared-key", "badge", { max: 600, windowSeconds: 3600 })).allowed).toBe(true);
  });

  it("opens a fresh window once the old one expires", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-26T10:00:00Z"));
    const policy = { max: 1, windowSeconds: 60 };
    expect((await checkRateLimit("ip-window", "shared-report", policy)).allowed).toBe(true);
    expect((await checkRateLimit("ip-window", "shared-report", policy)).allowed).toBe(false);
    vi.setSystemTime(new Date("2026-09-26T10:01:01Z"));
    expect((await checkRateLimit("ip-window", "shared-report", policy)).allowed).toBe(true);
  });
});

describe("getClientIp", () => {
  const req = (headers: Record<string, string | string[]>, remoteAddress?: string) =>
    ({ headers, socket: { remoteAddress } }) as unknown as NextApiRequest;

  it("takes the first x-forwarded-for entry", () => {
    expect(getClientIp(req({ "x-forwarded-for": "203.0.113.7, 10.0.0.1" }))).toBe("203.0.113.7");
  });

  it("falls back to the socket address, then 'unknown'", () => {
    expect(getClientIp(req({}, "127.0.0.1"))).toBe("127.0.0.1");
    expect(getClientIp(req({}))).toBe("unknown");
  });
});

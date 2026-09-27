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

  // The exact header shapes production delivered on 2026-09-27 (see
  // getClientIp's comment); 13.69.116.11 is the Static Web Apps edge.
  it("reads the client from Azure Static Web Apps' header", () => {
    expect(getClientIp(req({ "x-forwarded-for": "192.0.2.44:6302, 13.69.116.11:30230" }))).toBe("192.0.2.44");
  });

  it("can't be forged by sending X-Forwarded-For", () => {
    const forged = "203.0.113.9, 198.51.100.7, 192.0.2.44:6334, 13.69.116.11:1055";
    expect(getClientIp(req({ "x-forwarded-for": forged }))).toBe("192.0.2.44");
  });

  // The port changed on every request, so keying on it gave each connection
  // its own rate-limit bucket.
  it("is stable across source ports", () => {
    const a = getClientIp(req({ "x-forwarded-for": "192.0.2.44:6302, 13.69.116.11:30230" }));
    const b = getClientIp(req({ "x-forwarded-for": "192.0.2.44:6346, 13.69.116.11:14564" }));
    expect(a).toBe(b);
  });

  it("ignores the other client-settable headers", () => {
    const headers = {
      "x-forwarded-for": "192.0.2.44:6346, 13.69.116.11:14564",
      "x-client-ip": "203.0.113.10, 13.69.116.11",
      "x-azure-clientip": "203.0.113.11",
      "x-real-ip": "203.0.113.12",
    };
    expect(getClientIp(req(headers))).toBe("192.0.2.44");
  });

  it("honours TRUSTED_PROXY_HOPS for a one-hop topology", () => {
    vi.stubEnv("TRUSTED_PROXY_HOPS", "1");
    try {
      expect(getClientIp(req({ "x-forwarded-for": "203.0.113.9, 192.0.2.44" }))).toBe("192.0.2.44");
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("uses the only entry when there are fewer than the hop count (no proxy)", () => {
    expect(getClientIp(req({ "x-forwarded-for": "203.0.113.7" }))).toBe("203.0.113.7");
  });

  it("unwraps an IPv4-mapped socket address", () => {
    expect(getClientIp(req({}, "::ffff:127.0.0.1"))).toBe("127.0.0.1");
  });

  it("falls back to the socket address, then 'unknown'", () => {
    expect(getClientIp(req({}, "127.0.0.1"))).toBe("127.0.0.1");
    expect(getClientIp(req({}))).toBe("unknown");
  });
});

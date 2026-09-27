// Rate limiting shared by run-scan (and any other endpoint that needs it).
//
// Real implementation IF UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN
// are set (Upstash's Redis is HTTP-based, so no persistent connection or
// extra client library is needed — plain fetch works, keeping this
// dependency-free). Falls back to an in-memory bucket otherwise, which is
// fine for local dev but does NOT work correctly across multiple Function
// instances or after a cold start — see the warning below.

import type { NextApiRequest } from "next";
import { normaliseIp } from "./ipAllowlist";

// How many X-Forwarded-For entries, counted from the right, our own
// infrastructure appends. Measured against production on 2026-09-27 (via
// /api/client-ip, sending forged headers): Azure Static Web Apps delivers
//
//   X-Forwarded-For: <anything the client sent>, <client ip>:<port>, <SWA edge ip>:<port>
//
// Azure appends and never replaces, so everything left of the last two
// entries is whatever the caller chose to send. X-Client-IP is the edge's own
// address, and X-Azure-ClientIP / X-Real-IP pass through from the client
// untouched — none of them identify the caller. Override for a different
// topology (Azure Container Apps appends one hop: TRUSTED_PROXY_HOPS=1).
function trustedProxyHops(): number {
  const n = Number(process.env.TRUSTED_PROXY_HOPS);
  return Number.isInteger(n) && n >= 1 ? n : 2;
}

/**
 * The caller's IP address, for per-IP rate limits (routes with no owner to
 * key on, e.g. contact.ts) and API-key IP allowlists (apiAuth.ts) — which is
 * why it must never be a value the caller can forge. Port stripped: Azure's
 * "ip:port" form made every connection its own rate-limit bucket. Falls back
 * to the socket address when there's no proxy (local dev, e2e).
 */
export function getClientIp(req: NextApiRequest): string {
  const header = req.headers["x-forwarded-for"];
  const entries = (Array.isArray(header) ? header.join(",") : header ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);

  if (entries.length === 0) {
    const socket = req.socket?.remoteAddress;
    return (socket && normaliseIp(socket)) || socket || "unknown";
  }

  // Fewer entries than hops only happens off-platform (local dev, tests),
  // where there's no proxy to trust anyway.
  const hops = trustedProxyHops();
  const chosen = entries.length >= hops ? entries[entries.length - hops] : entries[0];
  return normaliseIp(chosen) ?? chosen;
}

export type RateLimitPolicy = { max: number; windowSeconds: number };

// 10 per hour suits expensive, deliberate actions (starting a scan, sending
// the contact form). Read-only public endpoints that are hit passively —
// an embedded badge loads on every page view of a customer's site, uptime
// monitors poll /api/health every minute — need their own, larger budget via
// the `policy` argument, or legitimate traffic would be throttled.
export const DEFAULT_RATE_LIMIT: RateLimitPolicy = { max: 10, windowSeconds: 60 * 60 };

const upstashUrl = process.env.UPSTASH_REDIS_REST_URL;
const upstashToken = process.env.UPSTASH_REDIS_REST_TOKEN;

export type RateLimitResult = { allowed: boolean; retryAfterSeconds: number };

// namespace keeps unrelated callers from sharing a bucket by accident —
// run-scan.ts and v1/scans.ts deliberately share "run-scan" (one combined
// scan-creation quota per owner regardless of entry point); a caller with a
// different purpose (e.g. contact.ts's spam protection) should pass its own.
export async function checkRateLimit(
  key: string,
  namespace: string = "run-scan",
  policy: RateLimitPolicy = DEFAULT_RATE_LIMIT
): Promise<RateLimitResult> {
  const namespacedKey = `${namespace}:${key}`;
  if (upstashUrl && upstashToken) {
    return checkRateLimitRedis(namespacedKey, policy);
  }
  return checkRateLimitInMemory(namespacedKey, policy);
}

/**
 * Real, shared-state rate limiting via Upstash Redis's REST API. Uses
 * INCR + EXPIRE (set only on the first increment in the window) — a
 * standard fixed-window counter. Not perfectly precise at window
 * boundaries (a burst could land 2x the limit split across two windows)
 * but simple and correct enough for this use case.
 *
 * TODO: switch to a sliding-window or token-bucket algorithm (Upstash
 * publishes a Lua script for this) if the fixed-window edge case becomes
 * a real problem in practice.
 */
async function checkRateLimitRedis(key: string, policy: RateLimitPolicy): Promise<RateLimitResult> {
  const redisKey = `ratelimit:${key}`;

  try {
    const incrRes = await fetch(`${upstashUrl}/incr/${encodeURIComponent(redisKey)}`, {
      headers: { Authorization: `Bearer ${upstashToken}` },
    });
    const { result: count } = (await incrRes.json()) as { result: number };

    if (count === 1) {
      // First request in this window — set expiry so the key self-cleans.
      await fetch(`${upstashUrl}/expire/${encodeURIComponent(redisKey)}/${policy.windowSeconds}`, {
        headers: { Authorization: `Bearer ${upstashToken}` },
      });
    }

    if (count > policy.max) {
      const ttlRes = await fetch(`${upstashUrl}/ttl/${encodeURIComponent(redisKey)}`, {
        headers: { Authorization: `Bearer ${upstashToken}` },
      });
      const { result: ttl } = (await ttlRes.json()) as { result: number };
      return { allowed: false, retryAfterSeconds: Math.max(ttl, 1) };
    }

    return { allowed: true, retryAfterSeconds: 0 };
  } catch (err) {
    // If Redis is unreachable, fail OPEN (allow the request) rather than
    // taking down scanning entirely because of a rate-limiter outage —
    // but log loudly so it gets noticed and fixed.
    console.error("[rateLimit] Upstash request failed, allowing request through:", err);
    return { allowed: true, retryAfterSeconds: 0 };
  }
}

// ---- In-memory fallback (dev only) ---------------------------------------
// TODO: this resets whenever the process recycles and does not share state
// across concurrently-running Function instances. Set UPSTASH_REDIS_REST_URL
// / UPSTASH_REDIS_REST_TOKEN before relying on rate limiting in production.
const inMemoryBuckets = new Map<string, { count: number; resetAt: number }>();

function checkRateLimitInMemory(key: string, policy: RateLimitPolicy): RateLimitResult {
  const now = Date.now();
  const windowMs = policy.windowSeconds * 1000;
  const bucket = inMemoryBuckets.get(key);

  if (!bucket || bucket.resetAt < now) {
    inMemoryBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, retryAfterSeconds: 0 };
  }
  if (bucket.count >= policy.max) {
    return { allowed: false, retryAfterSeconds: Math.ceil((bucket.resetAt - now) / 1000) };
  }
  bucket.count += 1;
  return { allowed: true, retryAfterSeconds: 0 };
}

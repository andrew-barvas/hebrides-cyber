// Rate limiting shared by run-scan (and any other endpoint that needs it).
//
// Real implementation IF UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN
// are set (Upstash's Redis is HTTP-based, so no persistent connection or
// extra client library is needed — plain fetch works, keeping this
// dependency-free). Falls back to an in-memory bucket otherwise, which is
// fine for local dev but does NOT work correctly across multiple Function
// instances or after a cold start — see the warning below.

import type { NextApiRequest } from "next";

// Best-effort client IP for unauthenticated routes that have no ownerId to
// key on (e.g. contact.ts). Azure Static Web Apps' Oryx-managed Functions
// sit behind Azure's CDN, which sets x-forwarded-for as
// "client, proxy1, proxy2, ..." — the first entry is the original client.
// Falls back to the socket address for local dev, where no proxy is present.
export function getClientIp(req: NextApiRequest): string {
  const forwarded = req.headers["x-forwarded-for"];
  const forwardedValue = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  if (forwardedValue) return forwardedValue.split(",")[0].trim();
  return req.socket.remoteAddress ?? "unknown";
}

const WINDOW_SECONDS = 60 * 60; // 1 hour
const MAX_REQUESTS = 10; // per key, per window

const upstashUrl = process.env.UPSTASH_REDIS_REST_URL;
const upstashToken = process.env.UPSTASH_REDIS_REST_TOKEN;

export type RateLimitResult = { allowed: boolean; retryAfterSeconds: number };

// namespace keeps unrelated callers from sharing a bucket by accident —
// run-scan.ts and v1/scans.ts deliberately share "run-scan" (one combined
// scan-creation quota per owner regardless of entry point); a caller with a
// different purpose (e.g. contact.ts's spam protection) should pass its own.
export async function checkRateLimit(key: string, namespace: string = "run-scan"): Promise<RateLimitResult> {
  const namespacedKey = `${namespace}:${key}`;
  if (upstashUrl && upstashToken) {
    return checkRateLimitRedis(namespacedKey);
  }
  return checkRateLimitInMemory(namespacedKey);
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
async function checkRateLimitRedis(key: string): Promise<RateLimitResult> {
  const redisKey = `ratelimit:${key}`;

  try {
    const incrRes = await fetch(`${upstashUrl}/incr/${encodeURIComponent(redisKey)}`, {
      headers: { Authorization: `Bearer ${upstashToken}` },
    });
    const { result: count } = (await incrRes.json()) as { result: number };

    if (count === 1) {
      // First request in this window — set expiry so the key self-cleans.
      await fetch(`${upstashUrl}/expire/${encodeURIComponent(redisKey)}/${WINDOW_SECONDS}`, {
        headers: { Authorization: `Bearer ${upstashToken}` },
      });
    }

    if (count > MAX_REQUESTS) {
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

function checkRateLimitInMemory(key: string): RateLimitResult {
  const now = Date.now();
  const windowMs = WINDOW_SECONDS * 1000;
  const bucket = inMemoryBuckets.get(key);

  if (!bucket || bucket.resetAt < now) {
    inMemoryBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, retryAfterSeconds: 0 };
  }
  if (bucket.count >= MAX_REQUESTS) {
    return { allowed: false, retryAfterSeconds: Math.ceil((bucket.resetAt - now) / 1000) };
  }
  bucket.count += 1;
  return { allowed: true, retryAfterSeconds: 0 };
}

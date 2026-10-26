// The one front door for every authenticated /api/v1 route. A route calls
//
//   const caller = await guardV1(req, res, "scans:read");
//   if (!caller) return;          // the response has already been written
//
// and gets, in order:
//   1. version + no-store headers on every response (success or error), so a
//      client can see which contract it spoke and no proxy caches account data;
//   2. failed-authentication throttling per client IP — bad credentials cost a
//      database lookup each, and a leaked-key hunt shouldn't be free;
//   3. authentication (key or session) → 401 `unauthorized`;
//   4. scope enforcement → 403 `insufficient_scope`;
//   5. a per-account request budget → 429 `rate_limited` with Retry-After.
//
// Errors keep the documented `{ error }` body and add a machine-readable
// `code`, which is additive and so safe within /v1.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, type ApiCaller } from "./apiAuth";
import { requireScope, type ApiScope } from "./apiScopes";
import { checkRateLimit, getClientIp, type RateLimitPolicy } from "./rateLimit";

/** Major version of the public contract. `/v1` changes are additive only. */
export const API_VERSION = "1";

// Polling a scan every few seconds from CI is normal, so reads get a generous
// budget; it still bounds a runaway loop or a scraper.
export const READ_RATE_LIMIT: RateLimitPolicy = { max: 1200, windowSeconds: 60 * 60 };
// Wrong credentials from one address. Legitimate clients rarely send any.
export const AUTH_FAILURE_LIMIT: RateLimitPolicy = { max: 30, windowSeconds: 10 * 60 };

export type GuardOptions = {
  /**
   * Apply the shared read budget. Default true. Routes that already enforce
   * their own, stricter budget (queueing a scan, dependency checks) pass false
   * so one request isn't charged twice.
   */
  rateLimit?: boolean;
};

export function setV1Headers(res: NextApiResponse): void {
  res.setHeader("X-API-Version", API_VERSION);
  // Account data: never cacheable by a shared proxy or the browser.
  res.setHeader("Cache-Control", "no-store");
}

function tooManyRequests(res: NextApiResponse, retryAfterSeconds: number, message = "Rate limit exceeded") {
  res.setHeader("Retry-After", String(retryAfterSeconds));
  res.status(429).json({ error: message, code: "rate_limited", retry_after_seconds: retryAfterSeconds });
}

export async function guardV1(
  req: NextApiRequest,
  res: NextApiResponse,
  scope: ApiScope,
  options: GuardOptions = {}
): Promise<ApiCaller | null> {
  setV1Headers(res);

  const ip = getClientIp(req);
  const caller = await authenticateApiRequest(req);

  if (!caller) {
    // Only failures spend this budget, so a client with good credentials is never slowed by it.
    const failures = await checkRateLimit(ip, "v1-auth-failure", AUTH_FAILURE_LIMIT);
    if (!failures.allowed) {
      tooManyRequests(res, failures.retryAfterSeconds, "Too many failed authentication attempts");
      return null;
    }
    res.status(401).json({
      error: "Missing or invalid Authorization header. Use: Authorization: Bearer <api-key>",
      code: "unauthorized",
    });
    return null;
  }

  if (!requireScope(caller, res, scope)) return null;

  if (options.rateLimit !== false) {
    const budget = await checkRateLimit(caller.ownerId, "v1-read", READ_RATE_LIMIT);
    if (!budget.allowed) {
      tooManyRequests(res, budget.retryAfterSeconds);
      return null;
    }
  }

  return caller;
}

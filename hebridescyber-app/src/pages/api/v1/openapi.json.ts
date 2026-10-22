// GET /api/v1/openapi.json — the machine-readable description of this API
// (OpenAPI 3.1), for SDK generators, Postman/Insomnia import and the CLI.
// Public by design — it describes the interface, never any account's data —
// so it is rate-limited by client IP rather than authenticated.
import type { NextApiRequest, NextApiResponse } from "next";
import { checkRateLimit, getClientIp, type RateLimitPolicy } from "@/lib/rateLimit";
import { buildOpenApiSpec } from "@/lib/openapi/spec";

const SPEC_RATE_LIMIT: RateLimitPolicy = { max: 60, windowSeconds: 3600 };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const limit = await checkRateLimit(getClientIp(req), "openapi-spec", SPEC_RATE_LIMIT);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds ?? 60));
    return res.status(429).json({ error: "Rate limit exceeded", retry_after_seconds: limit.retryAfterSeconds });
  }

  const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";
  res.setHeader("Cache-Control", "public, max-age=300");
  return res.status(200).json(buildOpenApiSpec(`${siteUrl}/api/v1`));
}

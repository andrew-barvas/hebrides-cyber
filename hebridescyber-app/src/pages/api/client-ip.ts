// GET /api/client-ip — the caller's own public IP address, as this API sees
// it (getClientIp, the same resolution the API-key allowlist and per-IP rate
// limits use). Backs "Add my current IP" in the allowlist UI: what matters is
// the address our edge reports, which isn't always what a third-party "what's
// my IP" site shows (a corporate proxy, a VPN split tunnel). Public and
// IP-rate-limited like /api/health; it only ever returns the caller's own
// address.
import type { NextApiRequest, NextApiResponse } from "next";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";

const CLIENT_IP_RATE_LIMIT = { max: 120, windowSeconds: 60 * 60 };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const ip = getClientIp(req);
  const { allowed, retryAfterSeconds } = await checkRateLimit(ip, "client-ip", CLIENT_IP_RATE_LIMIT);
  if (!allowed) {
    res.setHeader("Retry-After", String(retryAfterSeconds));
    return res.status(429).json({ error: "Too many requests" });
  }

  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ ip });
}

// GET /api/client-ip — the caller's own public IP address, as this API sees
// it. Backs "Add my current IP" in the API-key allowlist UI: what matters to
// an allowlist is the address our edge reports, which isn't always the one a
// third-party "what's my IP" site shows (IPv6 vs IPv4, a corporate proxy).
// Public and IP-rate-limited like /api/health; it only ever returns data
// about the caller's own request.
//
// TEMPORARY: `forwarding` echoes the proxy headers this request arrived with,
// to establish which of them Azure Static Web Apps sets and which a client
// can forge — the allowlist must key on one a client can't. Removed once
// that's measured in production.
import type { NextApiRequest, NextApiResponse } from "next";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";

const CLIENT_IP_RATE_LIMIT = { max: 120, windowSeconds: 60 * 60 };

const FORWARDING_HEADERS = [
  "x-forwarded-for",
  "x-client-ip",
  "client-ip",
  "x-azure-clientip",
  "x-azure-socketip",
  "x-real-ip",
  "x-original-forwarded-for",
  "forwarded",
  "x-forwarded-proto",
  "x-forwarded-host",
  "x-arr-log-id",
];

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const ip = getClientIp(req);
  const { allowed, retryAfterSeconds } = await checkRateLimit(ip, "client-ip", CLIENT_IP_RATE_LIMIT);
  if (!allowed) {
    res.setHeader("Retry-After", String(retryAfterSeconds));
    return res.status(429).json({ error: "Too many requests" });
  }

  const forwarding: Record<string, string | string[]> = {};
  for (const name of FORWARDING_HEADERS) {
    const value = req.headers[name];
    if (value !== undefined) forwarding[name] = value;
  }

  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ ip, forwarding, socket: req.socket.remoteAddress ?? null });
}

// POST { url } -> a passive TLS / headers / DNS check of any site, no account.
// See src/lib/instantCheck.ts for why that is safe to offer anonymously.
//
// Refuses to run without a shared rate-limit store in production: the
// in-memory fallback is per instance and resets on restart, so without Upstash
// anyone could point this service at a third party as often as they liked. The
// limiter also fails closed on a store outage, unlike the owner-keyed routes.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { checkRateLimit, getClientIp, hasSharedRateLimitStore } from "@/lib/rateLimit";
import { parseBody } from "@/lib/validate";
import { InstantCheckError, normaliseTarget, runInstantCheck } from "@/lib/instantCheck";

const bodySchema = z.object({ url: z.string().min(1).max(300) });

export const PER_IP = { max: 10, windowSeconds: 60 * 60 };
export const PER_TARGET = { max: 5, windowSeconds: 60 * 60 };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  res.setHeader("Cache-Control", "no-store");

  if (process.env.NODE_ENV === "production" && !hasSharedRateLimitStore()) {
    return res.status(503).json({ error: "The instant check is not available right now." });
  }

  const parsed = parseBody(bodySchema, req.body, res);
  if (!parsed) return;

  let origin: string;
  try {
    origin = normaliseTarget(parsed.url);
  } catch (err) {
    return res.status(400).json({ error: (err as Error).message });
  }

  const byIp = await checkRateLimit(getClientIp(req), "instant-check-ip", PER_IP, { failClosed: true });
  const byTarget = byIp.allowed ? await checkRateLimit(new URL(origin).hostname, "instant-check-target", PER_TARGET, { failClosed: true }) : byIp;
  if (!byIp.allowed || !byTarget.allowed) {
    res.setHeader("Retry-After", String(Math.max(byIp.retryAfterSeconds, byTarget.retryAfterSeconds, 1)));
    return res.status(429).json({ error: byIp.allowed ? "That site has been checked a lot recently. Please try again later." : "Too many checks from your network. Please try again later." });
  }

  try {
    return res.status(200).json(await runInstantCheck(origin));
  } catch (err) {
    if (err instanceof InstantCheckError) return res.status(422).json({ error: err.message });
    console.error("[instant-check]", (err as Error).message);
    return res.status(500).json({ error: "The check failed. Please try again." });
  }
}

// GET /api/health — E-04 (docs/ENHANCEMENTS.md). Public, unauthenticated
// (matches every real uptime-monitoring convention — an external monitor
// needs to hit this without a credential), and deliberately returns only
// booleans/counts, never a raw error message or stack trace, since this
// response is public by design.
//
// Sub-checks: Supabase (a real query via the service role, not just "is the
// client constructed"), Stripe (a real API call, not just "is the key
// string non-empty" — matches E-07's own lesson: an unset/invalid key
// should be visibly broken, not silently trusted), and scan_jobs queue
// depth (informational — a large backlog isn't the same failure class as
// "can't reach Supabase," so it never flips the overall status on its own,
// only if the count query itself fails to run).
import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/supabaseAdmin";
import { getStripe } from "@/lib/stripeClient";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";

const HEALTH_RATE_LIMIT = { max: 120, windowSeconds: 60 * 60 };

type CheckResult = { ok: boolean };
type QueueCheckResult = CheckResult & { depth: number | null };

async function checkSupabase(): Promise<CheckResult> {
  try {
    const { error } = await supabaseAdmin.from("users").select("id").limit(1);
    return { ok: !error };
  } catch {
    return { ok: false };
  }
}

async function checkStripe(): Promise<CheckResult> {
  try {
    await getStripe().balance.retrieve();
    return { ok: true };
  } catch {
    return { ok: false };
  }
}

async function checkQueue(): Promise<QueueCheckResult> {
  try {
    const { count, error } = await supabaseAdmin
      .from("scan_jobs")
      .select("id", { count: "exact", head: true })
      .eq("status", "pending");
    if (error) return { ok: false, depth: null };
    return { ok: true, depth: count ?? 0 };
  } catch {
    return { ok: false, depth: null };
  }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // HEAD too: UptimeRobot's free plan polls with HEAD, and a 405 there reads as "down".
  if (req.method !== "GET" && req.method !== "HEAD") return res.status(405).json({ error: "Method not allowed" });

  // Every call fans out to Supabase and Stripe, so an unthrottled public
  // health endpoint is a cheap way to burn someone else's API quota. 120/h
  // per IP comfortably fits a monitor polling once a minute.
  const limit = await checkRateLimit(getClientIp(req), "health", HEALTH_RATE_LIMIT);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many requests" });
  }

  const [supabase, stripe, queue] = await Promise.all([checkSupabase(), checkStripe(), checkQueue()]);

  // Queue depth is informational only — see module header. Only Supabase/
  // Stripe reachability (and the queue *check itself* succeeding, as
  // distinct from what depth it reports) determine overall health.
  const healthy = supabase.ok && stripe.ok && queue.ok;

  return res.status(healthy ? 200 : 503).json({
    status: healthy ? "ok" : "degraded",
    timestamp: new Date().toISOString(),
    checks: { supabase, stripe, queue },
  });
}

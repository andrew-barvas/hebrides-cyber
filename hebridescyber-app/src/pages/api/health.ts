// GET /api/health — E-04 (docs/ENHANCEMENTS.md). Public, unauthenticated
// (matches every real uptime-monitoring convention — an external monitor
// needs to hit this without a credential), and deliberately returns only
// booleans/counts, never a raw error message or stack trace, since this
// response is public by design.
//
// Sub-checks: Supabase (a real query via the service role, not just "is the
// client constructed"), Stripe (a real API call, not just "is the key
// string non-empty" — matches E-07's own lesson: an unset/invalid key
// should be visibly broken, not silently trusted), and the scan_jobs queue:
// depth plus the wait of the oldest pending job (src/lib/scanQueueWait.ts).
// Depth is informational — a large backlog isn't the same failure class as
// "can't reach Supabase," so it never flips the overall status on its own.
// The wait does, once SCAN_QUEUE_WAIT_ALERT=1: a job pending for over two
// hours means no worker is draining the queue, and the 503 is what pages the
// owner (UptimeRobot, and uptime.yml's incident issue). The query failing to
// run flips it too.
import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/supabaseAdmin";
import { getStripe } from "@/lib/stripeClient";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";
import { decideQueueWait, queueWaitAlertEnabled, queueWaitSeconds } from "@/lib/scanQueueWait";

const HEALTH_RATE_LIMIT = { max: 120, windowSeconds: 60 * 60 };

type CheckResult = { ok: boolean };
type QueueCheckResult = CheckResult & { depth: number | null; oldestWaitSeconds: number | null; waitExceeded: boolean };

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

const QUEUE_CHECK_FAILED: QueueCheckResult = { ok: false, depth: null, oldestWaitSeconds: null, waitExceeded: false };

async function checkQueue(): Promise<QueueCheckResult> {
  try {
    // One round trip: the exact pending count, plus the oldest pending row.
    const { data, count, error } = await supabaseAdmin
      .from("scan_jobs")
      .select("created_at", { count: "exact" })
      .eq("status", "pending")
      .order("created_at", { ascending: true })
      .limit(1);
    if (error) return QUEUE_CHECK_FAILED;
    const oldest = (data as { created_at: string }[] | null)?.[0]?.created_at ?? null;
    const waitSeconds = queueWaitSeconds(oldest, new Date());
    if (waitSeconds === null) return QUEUE_CHECK_FAILED;
    const wait = decideQueueWait(waitSeconds, { alertEnabled: queueWaitAlertEnabled() });
    return { ok: true, depth: count ?? 0, ...wait };
  } catch {
    return QUEUE_CHECK_FAILED;
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

  // Queue depth is informational only — see module header. Supabase/Stripe
  // reachability, the queue check itself succeeding, and (when the alert is
  // on) the oldest pending job's wait determine overall health.
  const healthy = supabase.ok && stripe.ok && queue.ok && !queue.waitExceeded;

  return res.status(healthy ? 200 : 503).json({
    status: healthy ? "ok" : "degraded",
    timestamp: new Date().toISOString(),
    checks: { supabase, stripe, queue },
  });
}

// Admin view of the scan_jobs queue (sql/migrations/008_scan_jobs.sql) —
// the free-tier Postgres + GitHub Actions worker queue, not the BullMQ+Redis
// one this replaced (src/worker/ was never wired to anything; deleted along
// with this route's old implementation, which always reported "not active"
// as a result).
import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin, supabaseAdmin } from "@/lib/adminAuth";

const RECENT_LIMIT = 20;

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  const [pendingCount, runningCount, completedCount, failedCount, recentRes] = await Promise.all([
    countByStatus("pending"),
    countByStatus("running"),
    countByStatus("completed"),
    countByStatus("failed"),
    supabaseAdmin
      .from("scan_jobs")
      .select("id, scan_id, target_url, status, created_at, claimed_at")
      .order("created_at", { ascending: false })
      .limit(RECENT_LIMIT),
  ]);

  const recent = recentRes.data ?? [];
  const format = (j: (typeof recent)[number]) => ({
    id: j.id,
    scanId: j.scan_id,
    targetUrl: j.target_url,
    addedAt: new Date(j.created_at).getTime(),
    startedAt: j.claimed_at ? new Date(j.claimed_at).getTime() : null,
    finishedAt: null, // scan_jobs doesn't track a separate completed-at column — see scans.created_at for that
    progress: j.status === "completed" || j.status === "failed" ? 100 : j.status === "running" ? 50 : 0,
  });

  return res.status(200).json({
    configured: true,
    stats: {
      waiting: pendingCount,
      active: runningCount,
      completed: completedCount,
      failed: failedCount,
      delayed: 0, // no equivalent concept in this queue design
    },
    jobs: {
      active: recent.filter((j) => j.status === "running").map(format),
      waiting: recent.filter((j) => j.status === "pending").map(format),
      failed: recent.filter((j) => j.status === "failed").map(format),
      completed: recent.filter((j) => j.status === "completed").map(format),
    },
  });
}

async function countByStatus(status: string): Promise<number> {
  const { count } = await supabaseAdmin
    .from("scan_jobs")
    .select("id", { count: "exact", head: true })
    .eq("status", status);
  return count ?? 0;
}

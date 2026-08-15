import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "./_auth";
// BullMQ imports — dynamic so the page doesn't break if bullmq isn't installed yet.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let bullmqModule: any = null;

async function loadBullmq() {
  if (bullmqModule) return bullmqModule;
  try {
    bullmqModule = await import("@/lib/queue");
    return bullmqModule;
  } catch {
    return null;
  }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  const adminId = await requireAdmin(req);
  if (!adminId) return res.status(403).json({ error: "Admin access required" });

  if (!process.env.REDIS_URL) {
    return res.status(200).json({ configured: false, note: "REDIS_URL is not set — queue is not active" });
  }

  const queue = await loadBullmq();
  if (!queue) {
    return res.status(200).json({ configured: false, note: "bullmq package not installed" });
  }

  const [stats, jobs] = await Promise.all([
    queue.getQueueStats(),
    queue.getRecentJobs(20),
  ]);

  const format = (j: Record<string, unknown>) => ({
    id: j.id,
    scanId: (j.data as Record<string, unknown>)?.scanId,
    targetUrl: (j.data as Record<string, unknown>)?.targetUrl,
    addedAt: j.timestamp,
    startedAt: j.processedOn ?? null,
    finishedAt: j.finishedOn ?? null,
    progress: j.progress ?? 0,
  });

  return res.status(200).json({
    configured: true,
    stats,
    jobs: {
      active: (jobs.active ?? []).map(format),
      waiting: (jobs.waiting ?? []).map(format),
      failed: (jobs.failed ?? []).map(format),
      completed: (jobs.completed ?? []).map(format),
    },
  });
}

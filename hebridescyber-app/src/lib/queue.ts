// BullMQ queue setup for the async scan worker architecture.
//
// The run-scan Azure Function enqueues jobs here; the long-running Docker
// worker container consumes them. Both sides import from this module.
//
// getRedisConnection() returns null (not throws) when REDIS_URL is absent so
// the Function can fall back to inline scanning in local dev without Redis.

import { Queue, type Job } from "bullmq";
import IORedis from "ioredis";

// ---- Types -----------------------------------------------------------------

export type ScanJobData = {
  scanId: string;
  targetUrl: string;
  ownerId: string;
};

export type ScanJobResult = {
  score: number;
  summary: string;
  findingsCount: number;
};

// ---- Redis singleton -------------------------------------------------------

let _redis: IORedis | null | undefined; // undefined = not yet initialised

export function getRedisConnection(): IORedis | null {
  if (_redis !== undefined) return _redis;

  const url = process.env.REDIS_URL;
  if (!url) {
    _redis = null;
    return null;
  }

  _redis = new IORedis(url, {
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
  });

  _redis.on("error", (err) => {
    console.error("[queue] Redis error:", err.message);
  });

  return _redis;
}

// ---- Queue -----------------------------------------------------------------

const QUEUE_NAME = "scans";

export function createScanQueue(): Queue<ScanJobData, ScanJobResult> | null {
  const connection = getRedisConnection();
  if (!connection) return null;
  return new Queue<ScanJobData, ScanJobResult>(QUEUE_NAME, { connection });
}

// ---- Public helpers --------------------------------------------------------

/**
 * Add a scan job to the queue.
 * Returns the BullMQ job ID string, or null if Redis is not configured.
 */
export async function enqueueScan(data: ScanJobData): Promise<string | null> {
  const queue = createScanQueue();
  if (!queue) return null;

  const job = await queue.add("run-scan", data, {
    attempts: 3,
    backoff: {
      type: "exponential",
      delay: 5_000,
    },
    removeOnComplete: 1_000,
    removeOnFail: 500,
  });

  await queue.close();
  return job.id ?? null;
}

/**
 * Returns waiting/active/completed/failed/delayed counts, or null when Redis
 * is not available.
 */
export async function getQueueStats(): Promise<{
  waiting: number;
  active: number;
  completed: number;
  failed: number;
  delayed: number;
} | null> {
  const queue = createScanQueue();
  if (!queue) return null;

  const counts = await queue.getJobCounts(
    "waiting",
    "active",
    "completed",
    "failed",
    "delayed"
  );
  await queue.close();

  return {
    waiting: counts.waiting ?? 0,
    active: counts.active ?? 0,
    completed: counts.completed ?? 0,
    failed: counts.failed ?? 0,
    delayed: counts.delayed ?? 0,
  };
}

export type RecentJobEntry = {
  id: string | undefined;
  data: ScanJobData;
  timestamp: number;
  processedOn: number | undefined;
  finishedOn: number | undefined;
};

/**
 * Returns the most recent jobs across all states, or null when Redis is not
 * available.
 */
export async function getRecentJobs(count = 20): Promise<{
  active: RecentJobEntry[];
  waiting: RecentJobEntry[];
  failed: RecentJobEntry[];
  completed: RecentJobEntry[];
} | null> {
  const queue = createScanQueue();
  if (!queue) return null;

  function shape(jobs: Job<ScanJobData, ScanJobResult>[]): RecentJobEntry[] {
    return jobs.map((j) => ({
      id: j.id,
      data: j.data,
      timestamp: j.timestamp,
      processedOn: j.processedOn,
      finishedOn: j.finishedOn,
    }));
  }

  const [active, waiting, failed, completed] = await Promise.all([
    queue.getActive(0, count - 1),
    queue.getWaiting(0, count - 1),
    queue.getFailed(0, count - 1),
    queue.getCompleted(0, count - 1),
  ]);

  await queue.close();

  return {
    active: shape(active),
    waiting: shape(waiting),
    failed: shape(failed),
    completed: shape(completed),
  };
}

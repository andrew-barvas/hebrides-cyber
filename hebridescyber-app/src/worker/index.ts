// BullMQ worker entry point.
//
// Run with: node --require ts-node/register src/worker/index.ts
// Or in Docker: see worker.Dockerfile CMD.
//
// Consumes "scans" queue jobs, delegates to runner.ts, then marks each
// job completed or failed. Handles SIGTERM gracefully so the container
// can be stopped mid-scan without leaving scans stuck in "running".

import { Worker } from "bullmq";
import { getRedisConnection, type ScanJobData, type ScanJobResult } from "../lib/queue";
import { processScanJob } from "./runner";

const CONCURRENCY = parseInt(process.env.WORKER_CONCURRENCY ?? "2", 10);

async function main() {
  const connection = getRedisConnection();
  if (!connection) {
    console.error("[worker] REDIS_URL is not set — worker cannot start");
    process.exit(1);
  }

  console.log(`[worker] Starting (concurrency=${CONCURRENCY})`);

  const worker = new Worker<ScanJobData, ScanJobResult>(
    "scans",
    processScanJob,
    { connection, concurrency: CONCURRENCY }
  );

  worker.on("completed", (job) => {
    console.log(`[worker] Job ${job.id} completed — score: ${job.returnvalue?.score}`);
  });

  worker.on("failed", (job, err) => {
    console.error(`[worker] Job ${job?.id} failed: ${err.message}`);
  });

  worker.on("error", (err) => {
    console.error("[worker] Worker error:", err.message);
  });

  // Graceful shutdown on SIGTERM (Docker stop, Azure Container Apps scale-in).
  let stopping = false;
  async function shutdown() {
    if (stopping) return;
    stopping = true;
    console.log("[worker] SIGTERM received — draining current jobs…");
    await worker.close();
    console.log("[worker] Shutdown complete");
    process.exit(0);
  }

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((err) => {
  console.error("[worker] Fatal startup error:", err);
  process.exit(1);
});

// Did a scheduled scan run actually scan? (SPRINT-PLAN H3.)
//
// scheduled-scans.yml's `verify` job reads the scan_jobs its own run's
// shards claimed (claimed_by = "gha-<run_id>-<shard>") and the extended-tool
// block of each resulting scan_results row, then calls verifyScanRun(). Green
// CI and a "completed" scan prove nothing on their own: every extended tool
// can come back `not_configured` or `error` (a missing binary, a broken
// install) and the scan still completes with the base checks. This turns
// that into a failed job somebody sees.
//
// Pure: no I/O, so the verdict rules are unit-tested
// (scanRunVerification.test.ts). Evidence discipline applies: a scan whose
// result row is missing, or a tool whose status can't be read, is reported,
// never counted as completed.

export type ScanRunJob = {
  id: string;
  status: string;
  scan_id: string | null;
  last_error: string | null;
};

export type ScanRunResult = {
  scan_id: string;
  extended: Record<string, unknown> | null;
};

export type ScanRunVerdict = "ok" | "nothing_ran" | "fail";

export type ScanRunVerification = {
  verdict: ScanRunVerdict;
  jobs: { total: number; completed: number; failed: number; unfinished: number };
  scansWithExtended: number;
  /** tool -> status -> number of scans that reported it. */
  toolStatus: Record<string, Record<string, number>>;
  /** Tools that completed (or returned partial results) in at least one scan. */
  toolsCompleted: string[];
  problems: string[];
};

// "partial" is a run that reported what it saw (katana); it proves the tool ran.
const RAN_STATUSES = new Set(["completed", "partial"]);

function statusOf(value: unknown): string {
  if (value && typeof value === "object" && "status" in value && typeof (value as { status: unknown }).status === "string") {
    return (value as { status: string }).status;
  }
  return "unreadable";
}

export function verifyScanRun(jobs: ScanRunJob[], results: ScanRunResult[]): ScanRunVerification {
  const problems: string[] = [];
  const completedJobs = jobs.filter((j) => j.status === "completed");
  const failedJobs = jobs.filter((j) => j.status === "failed");
  const unfinished = jobs.length - completedJobs.length - failedJobs.length;

  const resultByScan = new Map(results.map((r) => [r.scan_id, r]));
  const toolStatus: Record<string, Record<string, number>> = {};
  let scansWithExtended = 0;

  for (const job of failedJobs) {
    problems.push(`job ${job.id} failed: ${(job.last_error ?? "no error recorded").slice(0, 200)}`);
  }
  if (unfinished > 0) problems.push(`${unfinished} job(s) were still pending or running when the shards finished`);

  for (const job of completedJobs) {
    // A completed job always has a scan, except one skipped as already done
    // (run-queued-scan-jobs.ts); its scan was verified by the run that did it.
    if (!job.scan_id) continue;
    const result = resultByScan.get(job.scan_id);
    if (!result) {
      problems.push(`scan ${job.scan_id} is marked completed but has no result row`);
      continue;
    }
    if (!result.extended) continue; // a safe-profile scan: base checks only
    scansWithExtended++;
    for (const [tool, value] of Object.entries(result.extended)) {
      const status = statusOf(value);
      toolStatus[tool] ??= {};
      toolStatus[tool][status] = (toolStatus[tool][status] ?? 0) + 1;
    }
  }

  const toolsCompleted = Object.entries(toolStatus)
    .filter(([, counts]) => Object.keys(counts).some((s) => RAN_STATUSES.has(s)))
    .map(([tool]) => tool)
    .sort();

  let verdict: ScanRunVerdict;
  if (jobs.length === 0) {
    verdict = "nothing_ran";
  } else if (completedJobs.length === 0) {
    problems.push("no claimed job completed");
    verdict = "fail";
  } else if (scansWithExtended > 0 && toolsCompleted.length === 0) {
    problems.push(`${scansWithExtended} scan(s) ran the extended tier but no tool completed in any of them`);
    verdict = "fail";
  } else if (problems.some((p) => p.includes("has no result row"))) {
    verdict = "fail";
  } else {
    verdict = "ok";
  }

  return {
    verdict,
    jobs: { total: jobs.length, completed: completedJobs.length, failed: failedJobs.length, unfinished },
    scansWithExtended,
    toolStatus,
    toolsCompleted,
    problems,
  };
}

/** Markdown for the job summary ($GITHUB_STEP_SUMMARY). */
export function formatScanRunSummary(v: ScanRunVerification): string {
  const head = {
    ok: "✅ Scheduled scan run verified",
    nothing_ran: "ℹ️ No scan jobs were due, so there was nothing to verify",
    fail: "❌ Scheduled scan run did not prove it scanned",
  }[v.verdict];
  const lines = [
    `## ${head}`,
    "",
    `Jobs: ${v.jobs.total} claimed, ${v.jobs.completed} completed, ${v.jobs.failed} failed, ${v.jobs.unfinished} unfinished. Scans with extended tools: ${v.scansWithExtended}.`,
    "",
  ];
  const tools = Object.keys(v.toolStatus).sort();
  if (tools.length > 0) {
    lines.push("| Tool | Statuses |", "|---|---|");
    for (const tool of tools) {
      const counts = Object.entries(v.toolStatus[tool])
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([status, n]) => `${status} ×${n}`)
        .join(", ");
      lines.push(`| ${tool} | ${counts} |`);
    }
    lines.push("");
  }
  if (v.problems.length > 0) {
    lines.push("**Problems**", "", ...v.problems.map((p) => `- ${p}`), "");
  }
  return lines.join("\n");
}

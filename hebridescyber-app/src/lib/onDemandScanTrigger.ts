// Shared by every path that enqueues an on-demand (not scheduled) scan job —
// today that's src/pages/api/run-scan.ts (dashboard button) and
// src/pages/api/v1/scans.ts (public API) — so both get a fast turnaround via
// the same GitHub Actions dispatch rather than one of them drifting.
//
// Extracted out of run-scan.ts, where this originated, once v1/scans.ts
// needed the identical behaviour rather than a second copy.

// This repo's own identity, for dispatching .github/workflows/on-demand-scan.yml
// — not customer-supplied, so it's a constant rather than an input like
// generate-fix-pr.ts's githubRepo.
const OWN_GITHUB_REPO = "andrew-barvas/hebrides-cyber";

/**
 * Best-effort trigger for the on-demand-scan.yml workflow, so a queued job
 * gets picked up in roughly a minute instead of waiting for
 * scheduled-scans.yml's next daily cron. Never throws — GITHUB_PAT being
 * unset, or GitHub's API being briefly unavailable, must never turn a
 * successful "queued" response into a 500, since the job is safely queued
 * either way and the daily cron is a real fallback, just a slower one.
 *
 * Returns true if the dispatch succeeded, false otherwise — callers can
 * use this to surface better feedback to the user about expected wait time.
 */
export async function triggerOnDemandWorkflow(): Promise<boolean> {
  const pat = process.env.GITHUB_PAT;
  if (!pat) {
    console.warn("[onDemandScanTrigger] GITHUB_PAT not set — queued scan will wait for the next scheduled-scans.yml cron.");
    return false;
  }
  try {
    const res = await fetch(
      `https://api.github.com/repos/${OWN_GITHUB_REPO}/actions/workflows/on-demand-scan.yml/dispatches`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${pat}`,
          Accept: "application/vnd.github+json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ref: "master" }),
        signal: AbortSignal.timeout(6_000),
      }
    );
    if (!res.ok) {
      console.warn(`[onDemandScanTrigger] on-demand-scan.yml dispatch failed (${res.status}) — falling back to the daily cron.`);
      return false;
    }
    return true;
  } catch (err) {
    console.warn("[onDemandScanTrigger] on-demand-scan.yml dispatch threw — falling back to the daily cron:", (err as Error).message);
    return false;
  }
}

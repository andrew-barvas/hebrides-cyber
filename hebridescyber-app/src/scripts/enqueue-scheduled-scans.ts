// Used by .github/workflows/scheduled-scans.yml to enqueue one scan_jobs row
// per (active-subscription owner, monitored target) pair, replacing the old
// "build an HTTP matrix and curl run-scan per target" approach — see
// sql/migrations/008_scan_jobs.sql and src/scripts/run-queued-scan-jobs.ts.
//
// Only enqueues targets with a real, on-file domain verification
// (verifications.verified_at) — the old approach relied on run-scan's own
// step-2 gate to reject unverified targets at call time; this script now
// does that filtering itself, since the queued worker runs the scan
// directly rather than calling run-scan. See src/lib/ownership.ts's
// isDomainVerified for why this doesn't just re-check DNS live.
//
// Run locally with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... npx tsx src/scripts/enqueue-scheduled-scans.ts

import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import { isDomainVerified } from "../lib/ownership";
import { isScanDue, type Plan } from "../lib/scanCadence";
import { isWithinScanWindow } from "../lib/scanWindows";

async function main() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }

  // Same Node-20-CI-runner WebSocket workaround as fetch-scheduled-targets.ts
  // — createClient() constructs a RealtimeClient unconditionally even though
  // this script never subscribes to a channel.
  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    realtime: { transport: ws as unknown as WebSocketLikeConstructor },
  });

  const { data: activeSubs, error: subsError } = await supabaseAdmin
    .from("subscriptions")
    .select("owner, plan")
    .eq("status", "active");

  if (subsError) {
    console.error("Failed to fetch active subscriptions:", subsError.message);
    process.exit(1);
  }

  const activeOwners = (activeSubs ?? []).map((s) => s.owner);
  if (activeOwners.length === 0) {
    console.log("No active subscriptions — nothing to enqueue.");
    return;
  }

  // owner -> plan, so the per-target interval check below knows which
  // cadence (see src/lib/scanCadence.ts) applies without a second lookup.
  const ownerPlans = new Map<string, Plan>((activeSubs ?? []).map((s) => [s.owner, s.plan as Plan]));

  const { data: targets, error: targetsError } = await supabaseAdmin
    .from("monitored_targets")
    .select("owner, target_url, scan_window_start, scan_window_end, scan_window_tz")
    .in("owner", activeOwners);

  if (targetsError) {
    console.error("Failed to fetch monitored targets:", targetsError.message);
    process.exit(1);
  }

  let enqueued = 0;
  let skippedUnverified = 0;
  let skippedAlreadyQueued = 0;
  let skippedTooRecent = 0;
  let skippedOutsideWindow = 0;

  for (const target of targets ?? []) {
    if (!(await isDomainVerified(supabaseAdmin, target.owner, target.target_url))) {
      skippedUnverified++;
      continue;
    }

    if (!isWithinScanWindow({
      startTime: target.scan_window_start ?? null,
      endTime: target.scan_window_end ?? null,
      timezone: target.scan_window_tz ?? "UTC",
    }, new Date())) {
      skippedOutsideWindow++;
      continue;
    }

    const { data: existing } = await supabaseAdmin
      .from("scan_jobs")
      .select("id")
      .eq("owner", target.owner)
      .eq("target_url", target.target_url)
      .in("status", ["pending", "running"])
      .maybeSingle();

    if (existing) {
      skippedAlreadyQueued++;
      continue;
    }

    // Plan-tier cadence gate (see src/lib/scanCadence.ts): skip targets that
    // were completed too recently for their owner's plan. No new column —
    // this just looks at the most recent completed `scans` row for this
    // (owner, target_url) pair.
    const plan = ownerPlans.get(target.owner);
    if (plan) {
      const { data: lastScan } = await supabaseAdmin
        .from("scans")
        .select("created_at")
        .eq("owner", target.owner)
        .eq("target_url", target.target_url)
        .eq("status", "completed")
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();

      if (!isScanDue(plan, lastScan?.created_at ?? null, new Date())) {
        skippedTooRecent++;
        continue;
      }
    }

    const { error: insertError } = await supabaseAdmin
      .from("scan_jobs")
      .insert({ owner: target.owner, target_url: target.target_url });

    if (insertError) {
      console.error(`Failed to enqueue ${target.target_url} for ${target.owner}:`, insertError.message);
      continue;
    }
    enqueued++;
  }

  console.log(
    `Enqueued ${enqueued} scan job(s). Skipped ${skippedUnverified} unverified, ` +
      `${skippedAlreadyQueued} already-queued, ${skippedTooRecent} not-yet-due, ${skippedOutsideWindow} outside-window.`
  );
}

main().catch((err) => {
  console.error("enqueue-scheduled-scans failed:", err);
  process.exit(1);
});

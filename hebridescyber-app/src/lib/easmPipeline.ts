// SCALE-2: standalone External Attack Surface Management (EASM) discovery.
//
// EASM discovery already runs as a side effect of every scan
// (`runEasmDiscovery` called from `executeScan` Phase 2 — see CLAUDE.md
// "EASM discovery"). That couples discovery to the scan cadence: a Basic
// account scanned weekly only discovers new subdomains weekly, and an account
// between scans discovers nothing. This module runs the *same*
// `runEasmDiscovery` on its own, more frequent schedule, independent of
// whether a full scan is due — so a newly-certificated subdomain is found
// within hours, not at the next scan.
//
// It reuses, and does not duplicate:
//   - `runEasmDiscovery` (the crt.sh + optional DNS-brute discovery itself),
//   - the active-subscription + verified-target enumeration from
//     `enqueue-scheduled-scans.ts`,
//   - the `asset_inventory` "pending row, no notified_at" convention that
//     `sendAttackSurfaceAlerts` consumes on the next scheduled scan.
//
// Deliberately NOT done here: brute-force (that stays gated behind the Tier A
// offensive profile in the scan path — a standalone sweep must never run it),
// and alerting (pending rows are picked up by the next scan's
// `sendAttackSurfaceAlerts`, which has the crt.sh cert-date evidence it needs;
// this job only populates the inventory). Both are explained in the per-scan
// call site's comment in `scanExecution.ts`.
import type { SupabaseClient } from "@supabase/supabase-js";
import { isDomainVerified } from "./ownership";
import { runEasmDiscovery } from "./easmDiscovery";
import { monitoredDomain } from "./attackSurfaceMonitor";

export type EasmPipelineResult = {
  targetsConsidered: number;
  targetsSwept: number;
  skippedUnverified: number;
  skippedNoDomain: number;
  newAssets: number;
  errors: number;
};

/**
 * Sweeps every verified monitored target of an active-subscription owner for
 * newly-discovered assets. Pure-ish: all I/O goes through the injected
 * `supabaseAdmin`; `discover` is injectable so the orchestration can be tested
 * without hitting crt.sh. Never throws for a single target — a failed sweep is
 * counted and the loop continues (same never-load-bearing contract as the
 * per-scan call).
 */
export async function runEasmPipeline(
  supabaseAdmin: SupabaseClient,
  opts: { dryRun?: boolean; discover?: typeof runEasmDiscovery } = {},
): Promise<EasmPipelineResult> {
  const discover = opts.discover ?? runEasmDiscovery;
  const result: EasmPipelineResult = {
    targetsConsidered: 0,
    targetsSwept: 0,
    skippedUnverified: 0,
    skippedNoDomain: 0,
    newAssets: 0,
    errors: 0,
  };

  const { data: activeSubs, error: subsError } = await supabaseAdmin
    .from("subscriptions")
    .select("owner")
    .eq("status", "active");
  if (subsError) throw new Error(`Failed to fetch active subscriptions: ${subsError.message}`);

  const activeOwners = [...new Set((activeSubs ?? []).map((s) => s.owner as string))];
  if (activeOwners.length === 0) return result;

  const { data: targets, error: targetsError } = await supabaseAdmin
    .from("monitored_targets")
    .select("owner, target_url")
    .in("owner", activeOwners);
  if (targetsError) throw new Error(`Failed to fetch monitored targets: ${targetsError.message}`);

  for (const target of targets ?? []) {
    result.targetsConsidered++;

    if (!(await isDomainVerified(supabaseAdmin, target.owner, target.target_url))) {
      result.skippedUnverified++;
      continue;
    }

    let domain: string | null;
    try {
      domain = monitoredDomain(new URL(target.target_url).hostname);
    } catch {
      domain = null;
    }
    if (!domain) {
      result.skippedNoDomain++;
      continue;
    }

    if (opts.dryRun) {
      result.targetsSwept++;
      continue;
    }

    try {
      // bruteForce stays false: it is Tier-A-offensive-gated in the scan path
      // and must never run from an untriggered standalone sweep.
      const sweep = await discover(supabaseAdmin, target.owner, domain, { bruteForce: false });
      result.targetsSwept++;
      result.newAssets += sweep.newAssets;
    } catch {
      result.errors++;
    }
  }

  return result;
}

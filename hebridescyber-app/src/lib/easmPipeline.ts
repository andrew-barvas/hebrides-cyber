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
//   - the `asset_inventory` "pending row, no notified_at" convention, and the
//     alert's claim/evidence rules, via `sendSweepHostnameAlerts`.
//
// After each target's discovery it sends the new-hostname alert itself, using
// the certificate dates discovery just read, so an owner hears within hours
// instead of at their next scan (a week away on a weekly plan). Nothing is
// decided when crt.sh could not be read: those rows stay pending.
//
// Deliberately NOT done here: brute-force (that stays gated behind the Tier A
// offensive profile in the scan path — a standalone sweep must never run it)
// and DNS-change alerts (they need the stored snapshot's claim logic and stay
// with the scan path).
import type { SupabaseClient } from "@supabase/supabase-js";
import { isDomainVerified } from "./ownership";
import { runEasmDiscovery } from "./easmDiscovery";
import { monitoredDomain, sendSweepHostnameAlerts } from "./attackSurfaceMonitor";

export type EasmPipelineResult = {
  targetsConsidered: number;
  targetsSwept: number;
  skippedUnverified: number;
  skippedNoDomain: number;
  newAssets: number;
  errors: number;
  /** Targets whose crt.sh lookup failed: swept, but no certificate evidence, so no alert decision. */
  ctFailed: number;
  /** New hostnames owners were told about. */
  hostnamesReported: number;
  /** Targets where an alert was due but could not be delivered (released to retry). */
  alertFailures: number;
};

/**
 * Sweeps every verified monitored target of an active-subscription owner for
 * newly-discovered assets, then alerts the owner to any new hostname. Pure-ish:
 * all I/O goes through the injected `supabaseAdmin`; `discover` and `alert` are
 * injectable so the orchestration can be tested without hitting crt.sh or
 * sending email. Never throws for a single target — a failed sweep or alert is
 * counted and the loop continues (same never-load-bearing contract as the
 * per-scan call).
 */
export async function runEasmPipeline(
  supabaseAdmin: SupabaseClient,
  opts: { dryRun?: boolean; discover?: typeof runEasmDiscovery; alert?: typeof sendSweepHostnameAlerts } = {},
): Promise<EasmPipelineResult> {
  const discover = opts.discover ?? runEasmDiscovery;
  const alert = opts.alert ?? sendSweepHostnameAlerts;
  const result: EasmPipelineResult = {
    targetsConsidered: 0,
    targetsSwept: 0,
    skippedUnverified: 0,
    skippedNoDomain: 0,
    newAssets: 0,
    errors: 0,
    ctFailed: 0,
    hostnamesReported: 0,
    alertFailures: 0,
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

    let sweep: Awaited<ReturnType<typeof runEasmDiscovery>>;
    try {
      // bruteForce stays false: it is Tier-A-offensive-gated in the scan path
      // and must never run from an untriggered standalone sweep. targetUrl is
      // the monitored site, so the rows match what that site's scans look for.
      sweep = await discover(supabaseAdmin, target.owner, domain, { bruteForce: false, targetUrl: target.target_url });
      result.targetsSwept++;
      result.newAssets += sweep.newAssets;
      if (!sweep.ctRead) result.ctFailed++;
    } catch {
      result.errors++;
      continue;
    }

    // Alert even when nothing was discovered this run: rows left pending by an
    // earlier crt.sh failure or a failed delivery are decided (or retried) here.
    try {
      const sent = await alert(
        supabaseAdmin,
        target.owner,
        target.target_url,
        { firstCertificates: sweep.firstCertificates ?? new Map(), ctRead: Boolean(sweep.ctRead) },
      );
      if (sent.reported) result.hostnamesReported += sent.reported.newHostnames.length;
      if (sent.errors.length > 0 && !sent.delivered) result.alertFailures++;
    } catch {
      result.alertFailures++;
    }
  }

  return result;
}

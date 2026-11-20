// Re-checks the offensive gate while an offensive scan runs, and halts the
// scan's tools the moment it no longer passes (src/lib/toolHalt.ts). The gate
// at claim time decides whether a run may start; this decides whether it may
// carry on. So stopping an engagement, revoking an authorisation, the window or
// a testing window closing, the engagement expiring or the plan lapsing all stop
// a run already under way, within one interval.
//
// Fail-closed: a check that throws halts the run, like a refusal.
import type { SupabaseClient } from "@supabase/supabase-js";
import { logAuditEvent } from "./audit";
import { describeRefusal, evaluateOffensiveGate, type OffensiveGateDecision } from "./offensiveGate";
import { HaltController, runWithHalt } from "./toolHalt";

/** How often the gate is asked again during an offensive run. */
export const WATCHDOG_INTERVAL_MS = 20_000;

export type Watchdog = { stop: () => void };

/** Why the watchdog halted a run: a gate refusal, or a check that threw. */
export type HaltDecision = Extract<OffensiveGateDecision, { allowed: false }> | { allowed: false; reason: "check_failed" };

/** The sentence a halted scan's error detail carries, e.g. "Testing was stopped part-way: <this>". */
export function haltText(decision: HaltDecision): string {
  return decision.reason === "check_failed" ? "the authorisation could not be re-checked" : describeRefusal(decision);
}

export function startOffensiveWatchdog(options: {
  controller: HaltController;
  check: () => Promise<OffensiveGateDecision>;
  onHalt: (decision: HaltDecision) => void | Promise<void>;
  intervalMs?: number;
}): Watchdog {
  const { controller, check, onHalt, intervalMs = WATCHDOG_INTERVAL_MS } = options;
  let stopped = false;
  let checking = false;

  const tick = async () => {
    if (stopped || checking || controller.halted) return;
    checking = true;
    let decision: OffensiveGateDecision | HaltDecision;
    try {
      decision = await check();
    } catch {
      decision = { allowed: false, reason: "check_failed" };
    }
    checking = false;
    if (stopped || decision.allowed || controller.halted) return;
    controller.halt(haltText(decision));
    try {
      await onHalt(decision);
    } catch {
      // Recording the halt is best-effort; the tools are already stopped.
    }
  };

  const timer = setInterval(() => void tick(), intervalMs);
  timer.unref?.();
  return {
    stop: () => {
      stopped = true;
      clearInterval(timer);
    },
  };
}

/**
 * Runs an offensive scan under a halt controller with the watchdog asking the
 * gate again throughout. A halt is audited as `offensive_scan.halted` on the
 * job, with the engagement, so the engagement's history shows the stop took
 * effect on a run already under way.
 */
export async function runOffensiveScan<T>(
  admin: SupabaseClient,
  job: { id: string; owner: string; target_url: string },
  scanId: string,
  engagementId: string | null,
  run: () => Promise<T>,
  options: { intervalMs?: number; check?: () => Promise<OffensiveGateDecision> } = {},
): Promise<T> {
  const controller = new HaltController();
  const watchdog = startOffensiveWatchdog({
    controller,
    intervalMs: options.intervalMs,
    check: options.check ?? (() => evaluateOffensiveGate(admin, job.owner, job.target_url)),
    onHalt: async (decision) => {
      const reason = decision.reason;
      const scopeRefusal = "scopeRefusal" in decision ? (decision.scopeRefusal ?? null) : null;
      console.warn(`[job ${job.id}] offensive run halted part-way (${reason}${scopeRefusal ? `: ${scopeRefusal}` : ""}); stopping its tools`);
      await logAuditEvent(admin, {
        actorId: job.owner,
        action: "offensive_scan.halted",
        resourceType: "scan_job",
        resourceId: job.id,
        metadata: { target_url: job.target_url, scan_id: scanId, engagement_id: engagementId, reason, scope_refusal: scopeRefusal, tools_running: controller.running },
      });
    },
  });
  try {
    return await runWithHalt(controller, run);
  } finally {
    watchdog.stop();
  }
}

// The offensive-tools gate (docs/EXPLOITABILITY-ENGINE.md §10.2,
// docs/EXPLOIT-PRODUCT-PLAN.md "Gate extension"). run-queued-scan-jobs.ts asks
// this before any configuration that enables an offensive-only tool, and the
// halt watchdog asks it again while one runs. It is the only place the
// offensive suite is unlocked.
//
// An offensive run needs, all at once:
//   1. the owner on Tier A (planAccess, status-aware),
//   2. a current per-target authorisation (offensive_scan_authorizations),
//   3. when that authorisation was signed for an engagement: the target inside
//      that engagement's signed scope, now (checkScope "active": state
//      authorised/in_window, inside the window and any testing window, before
//      the expiry, host listed and not excluded, domain verified, authorisation
//      linked to this engagement), and the engagement allowing the offensive
//      profile.
// Domain ownership is checked by the worker before this runs, and again by
// checkScope for an engagement.
//
// A legacy Tier A authorisation with no engagement keeps today's behaviour
// unless OFFENSIVE_REQUIRE_ENGAGEMENT=1, which makes an engagement mandatory for
// every offensive run. Whether to turn that on at launch is the owner's call
// (EXPLOITABILITY-ENGINE.md §13 Q2).
//
// Fail-closed: every lookup here degrades to "no", never to "yes".
import type { SupabaseClient } from "@supabase/supabase-js";
import { logAuditEvent } from "./audit";
import { loadEngagementScopeFacts } from "./exploitability/load";
import { checkScope } from "./exploitability/scope/scopeGuard";
import type { ScopeRefusal } from "./exploitability/types";
import { authHostFromUrl, loadCurrentOffensiveAuthorization } from "./offensiveAuthorization";
import { hasTierAAccess } from "./planAccess";

export type OffensiveRefusal = "not_tier_a" | "no_authorization" | "engagement_required" | "out_of_engagement_scope" | "engagement_profile_disallows";

export type OffensiveGateDecision =
  | { allowed: true; engagementId: string | null }
  | { allowed: false; reason: OffensiveRefusal; engagementId: string | null; scopeRefusal?: ScopeRefusal };

/** Is an engagement mandatory for every offensive run? Off unless the owner turns it on. */
export function requireEngagementForOffensive(env: Record<string, string | undefined> = process.env): boolean {
  return env.OFFENSIVE_REQUIRE_ENGAGEMENT === "1";
}

const REASON_TEXT: Record<OffensiveRefusal, string> = {
  not_tier_a: "owner is not on Tier A",
  no_authorization: "no current offensive-scan authorization for this target",
  engagement_required: "offensive runs need an engagement and this authorization has none",
  out_of_engagement_scope: "target is outside the engagement's signed scope or window",
  engagement_profile_disallows: "the engagement doesn't allow the offensive profile",
};

/** A plain sentence for logs and the audit record. */
export function describeRefusal(decision: Extract<OffensiveGateDecision, { allowed: false }>): string {
  return decision.scopeRefusal ? `${REASON_TEXT[decision.reason]} (${decision.scopeRefusal})` : REASON_TEXT[decision.reason];
}

export async function evaluateOffensiveGate(
  admin: SupabaseClient,
  owner: string,
  targetUrl: string,
  now: Date = new Date(),
  options: { requireEngagement?: boolean } = {},
): Promise<OffensiveGateDecision> {
  const requireEngagement = options.requireEngagement ?? requireEngagementForOffensive();
  const [tierOk, authorization] = await Promise.all([
    hasTierAAccess(admin, owner).catch(() => false),
    loadCurrentOffensiveAuthorization(admin, owner, targetUrl, now),
  ]);
  if (!tierOk) return { allowed: false, reason: "not_tier_a", engagementId: authorization?.engagementId ?? null };
  if (!authorization) return { allowed: false, reason: "no_authorization", engagementId: null };

  const { engagementId } = authorization;
  if (!engagementId) {
    return requireEngagement ? { allowed: false, reason: "engagement_required", engagementId: null } : { allowed: true, engagementId: null };
  }

  const host = authHostFromUrl(targetUrl);
  if (!host) return { allowed: false, reason: "out_of_engagement_scope", engagementId, scopeRefusal: "host_not_in_scope" };
  const facts = await loadEngagementScopeFacts(admin, engagementId, host);
  // Linking already requires the same owner (checkAuthorizationLink); this is
  // defence in depth, so an authorisation can never borrow another account's engagement.
  if (facts.engagement && facts.engagement.owner !== owner) return { allowed: false, reason: "out_of_engagement_scope", engagementId, scopeRefusal: "engagement_not_found" };
  const scope = checkScope(host, facts, now, "active");
  if (!scope.ok) return { allowed: false, reason: "out_of_engagement_scope", engagementId, scopeRefusal: scope.reason };
  if (facts.engagement?.scanProfile !== "offensive") return { allowed: false, reason: "engagement_profile_disallows", engagementId };
  return { allowed: true, engagementId };
}

/**
 * Audits a gate decision against a scan job. A refusal is `offensive_scan.refused`
 * and, when an engagement was involved, `engagement_scope.refused` on the
 * engagement too, so its own history shows the attempt. A pass is
 * `offensive_scan.ran`, carrying the engagement id that tied it to a signed scope.
 * Best-effort, like every audit call: it never decides anything.
 */
export async function auditOffensiveGate(
  admin: SupabaseClient,
  job: { id: string; owner: string; target_url: string },
  decision: OffensiveGateDecision,
  profile: string,
): Promise<void> {
  if (decision.allowed) {
    await logAuditEvent(admin, {
      actorId: job.owner,
      action: "offensive_scan.ran",
      resourceType: "scan_job",
      resourceId: job.id,
      metadata: { target_url: job.target_url, profile, engagement_id: decision.engagementId },
    });
    return;
  }
  await logAuditEvent(admin, {
    actorId: job.owner,
    action: "offensive_scan.refused",
    resourceType: "scan_job",
    resourceId: job.id,
    metadata: {
      target_url: job.target_url,
      reason: describeRefusal(decision),
      code: decision.reason,
      scope_refusal: decision.scopeRefusal ?? null,
      profile,
      engagement_id: decision.engagementId,
    },
  });
  if (decision.engagementId && (decision.reason === "out_of_engagement_scope" || decision.reason === "engagement_profile_disallows")) {
    await logAuditEvent(admin, {
      actorId: job.owner,
      action: "engagement_scope.refused",
      resourceType: "engagement",
      resourceId: decision.engagementId,
      metadata: { host: authHostFromUrl(job.target_url), reason: decision.scopeRefusal ?? decision.reason, scan_job_id: job.id },
    });
  }
}

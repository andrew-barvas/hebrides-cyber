// Engagement records (migration 070): the reads and writes behind /api/engagements*
// (docs/EXPLOITABILITY-ENGINE.md §7). Database only: nothing here sends traffic,
// starts a scan or enqueues a job. Which moves are allowed is decided by the pure
// checkTransition; this file gathers its facts and writes the result.
//
// Engagements are created and scoped by an admin, never self-serve. The owner's
// own part is linking their authorisation (checkAuthorizationLink) and stopping
// the engagement (abortEngagement).
import type { NextApiResponse } from "next";
import type { SupabaseClient } from "@supabase/supabase-js";
import { respondInternalError } from "./apiError";
import { logAuditEvent } from "./audit";
import { isMissingSchemaError } from "./dbErrors";
import type { TransitionFacts } from "./exploitability/scope/engagementState";
import { normaliseScopeHost } from "./exploitability/scope/scopeGuard";
import type { EngagementState } from "./exploitability/types";
import { isAuthorizationCurrent } from "./offensiveAuthorization";
import { isDomainVerified } from "./ownership";

export const ENGAGEMENT_COLUMNS =
  "id, owner, reference, state, scan_profile, window_start, window_end, contract_signed_at, contract_signed_by_name, contract_signed_by_role, created_at, closed_at, aborted_at, abort_reason";

export type EngagementRow = {
  id: string;
  owner: string;
  reference: string;
  state: EngagementState;
  scan_profile: "safe" | "exposure" | "offensive";
  window_start: string | null;
  window_end: string | null;
  contract_signed_at: string | null;
  contract_signed_by_name: string | null;
  contract_signed_by_role: string | null;
  created_at: string;
  closed_at: string | null;
  aborted_at: string | null;
  abort_reason: string | null;
};

type DbError = { code?: string; message?: string };
export type EngagementFailure = { status: "not_found" | "unavailable" } | { status: "error"; error: DbError };
export type EngagementResult<T> = { status: "ok"; data: T } | EngagementFailure;

const failure = (error: DbError): EngagementFailure => (isMissingSchemaError(error) ? { status: "unavailable" } : { status: "error", error });

/** Answers for a load or write that didn't succeed. */
export function sendEngagementFailure(res: NextApiResponse, route: string, failed: EngagementFailure): void {
  if (failed.status === "error") respondInternalError(res, route, failed.error, { publicMessage: "Could not complete the engagement request" });
  else if (failed.status === "unavailable") res.status(503).json({ error: "Engagements aren't available yet." });
  else res.status(404).json({ error: "Engagement not found." });
}

export async function loadEngagement(admin: SupabaseClient, id: string): Promise<EngagementResult<EngagementRow>> {
  const { data, error } = await admin.from("engagements").select(ENGAGEMENT_COLUMNS).eq("id", id).maybeSingle();
  if (error) return failure(error);
  if (!data) return { status: "not_found" };
  return { status: "ok", data: data as unknown as EngagementRow };
}

export async function accountExists(admin: SupabaseClient, id: string): Promise<EngagementResult<boolean>> {
  const { data, error } = await admin.from("users").select("id").eq("id", id).maybeSingle();
  if (error) return failure(error);
  return { status: "ok", data: Boolean(data) };
}

/**
 * Writes `changes` only if the engagement is still in the state the decision was
 * made from. A null result means someone else moved it first, so the caller
 * refuses rather than overwriting.
 */
export async function updateEngagement(admin: SupabaseClient, id: string, fromState: EngagementState, changes: Record<string, unknown>): Promise<EngagementResult<EngagementRow | null>> {
  const { data, error } = await admin.from("engagements").update(changes).eq("id", id).eq("state", fromState).select(ENGAGEMENT_COLUMNS).maybeSingle();
  if (error) return failure(error);
  return { status: "ok", data: (data ?? null) as unknown as EngagementRow | null };
}

/** The facts for a move to `authorised`, fresh from the database. A failed read is a failure, never empty facts. */
export async function loadIncludedHostFacts(admin: SupabaseClient, engagement: Pick<EngagementRow, "id" | "owner">, now: Date): Promise<EngagementResult<TransitionFacts["includedHosts"]>> {
  const scope = await admin.from("engagement_scope_hosts").select("host").eq("engagement_id", engagement.id).eq("included", true).is("removed_at", null);
  if (scope.error) return failure(scope.error);

  const auths = await admin.from("offensive_scan_authorizations").select("target_host, revoked_at, expires_at").eq("owner", engagement.owner).eq("engagement_id", engagement.id).is("revoked_at", null);
  if (auths.error) return failure(auths.error);
  const authRows = (auths.data ?? []) as { target_host: string; revoked_at: string | null; expires_at: string | null }[];

  const hosts: TransitionFacts["includedHosts"][number][] = [];
  for (const { host } of (scope.data ?? []) as { host: string }[]) {
    hosts.push({
      host,
      domainVerified: await isDomainVerified(admin, engagement.owner, `https://${host}/`),
      authorizationLinkedAndCurrent: authRows.some((a) => a.target_host === host && isAuthorizationCurrent(a, now)),
    });
  }
  return { status: "ok", data: hosts };
}

export type ScopeAdd = { host: string; included: boolean; trustGroup?: string };
export type ScopeHostRefusal = { host: string; reason: "invalid_host" | "domain_not_verified" | "not_listed" };
export type ScopeChanges = {
  added: { host: string; included: boolean }[];
  removed: string[];
  refused: ScopeHostRefusal[];
};

/**
 * Applies a scope edit, removals first so a host can be swapped in one request.
 * Each host stands alone: a refused one doesn't stop the rest. An included host
 * needs a verified domain, while an exclusion doesn't, since it only ever narrows.
 * Every change is audited as it happens, so a failure partway leaves a true record.
 */
export async function applyScopeChanges(
  admin: SupabaseClient,
  engagement: Pick<EngagementRow, "id" | "owner">,
  actorId: string,
  changes: { add: readonly ScopeAdd[]; remove: readonly string[] },
): Promise<EngagementResult<ScopeChanges>> {
  const result: ScopeChanges = { added: [], removed: [], refused: [] };
  const audit = (action: string, metadata: Record<string, unknown>) =>
    logAuditEvent(admin, { actorId, action, resourceType: "engagement", resourceId: engagement.id, metadata });
  const refuse = async (host: string, reason: ScopeHostRefusal["reason"]) => {
    result.refused.push({ host, reason });
    await audit("engagement_scope.refused", { host, reason });
  };
  const softRemove = (host: string) =>
    admin.from("engagement_scope_hosts").update({ removed_at: new Date().toISOString() }).eq("engagement_id", engagement.id).eq("host", host).is("removed_at", null).select("host");

  for (const raw of changes.remove) {
    const host = normaliseScopeHost(raw);
    if (!host) {
      await refuse(raw, "invalid_host");
      continue;
    }
    const { data, error } = await softRemove(host);
    if (error) return failure(error);
    if (!data?.length) {
      await refuse(host, "not_listed");
      continue;
    }
    result.removed.push(host);
    await audit("engagement_scope.host_removed", { host });
  }

  for (const entry of changes.add) {
    const host = normaliseScopeHost(entry.host);
    if (!host) {
      await refuse(entry.host, "invalid_host");
      continue;
    }
    if (entry.included && !(await isDomainVerified(admin, engagement.owner, `https://${host}/`))) {
      await refuse(host, "domain_not_verified");
      continue;
    }
    // One active row per host: changing a host's in/out flag replaces its row, so the history stays.
    const { error: replaceError } = await softRemove(host);
    if (replaceError) return failure(replaceError);
    const { error } = await admin.from("engagement_scope_hosts").insert({
      engagement_id: engagement.id,
      owner: engagement.owner,
      host,
      included: entry.included,
      trust_group: entry.trustGroup ?? null,
      added_by: actorId,
    });
    if (error) return failure(error);
    result.added.push({ host, included: entry.included });
    await audit("engagement_scope.host_added", { host, included: entry.included });
  }
  return { status: "ok", data: result };
}

export type AuthorizationLinkRefusal = "state_disallows" | "host_not_in_scope";

/**
 * May the owner sign an authorisation for this host against this engagement?
 * Only the owner's own engagement, only before it is authorised, and only for a
 * host on its included list. This is what stops a new authorisation being tied
 * to an engagement that has already been stopped or finished.
 */
export async function checkAuthorizationLink(admin: SupabaseClient, owner: string, engagementId: string, host: string): Promise<EngagementResult<{ ok: true } | { ok: false; reason: AuthorizationLinkRefusal }>> {
  const loaded = await loadEngagement(admin, engagementId);
  if (loaded.status !== "ok") return loaded;
  if (loaded.data.owner !== owner) return { status: "not_found" };
  if (loaded.data.state !== "booked" && loaded.data.state !== "scoped") return { status: "ok", data: { ok: false, reason: "state_disallows" } };

  const { data, error } = await admin.from("engagement_scope_hosts").select("host").eq("engagement_id", engagementId).eq("host", host).eq("included", true).is("removed_at", null).maybeSingle();
  if (error) return failure(error);
  return { status: "ok", data: data ? { ok: true } : { ok: false, reason: "host_not_in_scope" } };
}

export type AbortOutcome = { outcome: "aborted" | "already_aborted"; from: EngagementState; revokedHosts: string[]; simulationsWithdrawn: number } | { outcome: "closed" } | { outcome: "not_found" };

/** Calls abort_engagement() (migration 073), which does the whole stop in one transaction. */
export async function abortEngagement(admin: SupabaseClient, id: string, reason: string | null): Promise<EngagementResult<AbortOutcome>> {
  const { data, error } = await admin.rpc("abort_engagement", { p_engagement_id: id, p_reason: reason });
  if (error) return error.code === "PGRST202" || error.code === "42883" ? { status: "unavailable" } : failure(error);
  const row = data as { outcome: AbortOutcome["outcome"]; from?: EngagementState; revoked_hosts?: string[]; simulations_withdrawn?: number };
  if (row.outcome === "closed") return { status: "ok", data: { outcome: "closed" } };
  if (row.outcome === "not_found") return { status: "ok", data: { outcome: "not_found" } };
  return { status: "ok", data: { outcome: row.outcome, from: row.from as EngagementState, revokedHosts: row.revoked_hosts ?? [], simulationsWithdrawn: row.simulations_withdrawn ?? 0 } };
}

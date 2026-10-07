// Tier A offensive scanning — per-scan authorization.
//
// The `offensive` scan profile (scanProfiles.ts) runs brute-force and, once the
// owner enables them, real-attack tools. Being on Tier A is necessary but not
// sufficient: the owner must also have recorded an explicit, per-target
// authorization acknowledging exactly what will be run against a host they
// control. This module is the single place that records and checks that
// authorization; run-queued-scan-jobs.ts consults `hasActiveOffensiveAuthorization`
// beside the existing domain-ownership check before an offensive scan runs.
//
// Table: offensive_scan_authorizations (migration 051), one ACTIVE row per
// (owner, target_host). No FK to auth.users, so the record of what was
// authorised survives account erasure (same as deletion_requests). Written only
// by the service role (the consent API route); owners read their own via RLS.
//
// Before migration 051 every read degrades to "no authorization" (never throws),
// so an offensive scan simply refuses rather than erroring — the safe default.

import type { SupabaseClient } from "@supabase/supabase-js";
import { isMissingSchemaError } from "./dbErrors";
import { logAuditEvent } from "./audit";

export type OffensiveAuthorizationRow = {
  owner: string;
  target_host: string;
  authorized_by: string;
  authorized_at: string;
  scope: string;
  expires_at: string | null;
  revoked_at: string | null;
};

/** The host key an authorization is stored under. Lowercased hostname; both the
 *  consent route and the worker derive it from the target URL the same way, so
 *  what matters is that they agree, not the exact normalisation. */
export function authHostFromUrl(targetUrl: string): string | null {
  try {
    return new URL(targetUrl).hostname.toLowerCase() || null;
  } catch {
    return null;
  }
}

/** Pure: is this authorization row usable right now? Not revoked, not expired. */
export function isAuthorizationCurrent(row: Pick<OffensiveAuthorizationRow, "revoked_at" | "expires_at">, now: Date): boolean {
  if (row.revoked_at) return false;
  if (row.expires_at && new Date(row.expires_at).getTime() <= now.getTime()) return false;
  return true;
}

/**
 * Does the owner have a current authorization for offensive scanning of this
 * target? Never throws — any read failure (including the table not existing
 * before migration 051) is treated as "not authorized", so the worker refuses
 * the offensive scan rather than running it on a failed read.
 */
export async function hasActiveOffensiveAuthorization(
  supabaseAdmin: SupabaseClient,
  owner: string,
  targetUrl: string,
  now: Date = new Date(),
): Promise<boolean> {
  const host = authHostFromUrl(targetUrl);
  if (!host) return false;
  try {
    const { data, error } = await supabaseAdmin
      .from("offensive_scan_authorizations")
      .select("revoked_at, expires_at")
      .eq("owner", owner)
      .eq("target_host", host)
      .is("revoked_at", null)
      .order("authorized_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    if (error || !data) return false;
    return isAuthorizationCurrent(data as OffensiveAuthorizationRow, now);
  } catch {
    return false;
  }
}

/**
 * Record an offensive-scanning authorization for a target. Revokes any existing
 * active authorization for the same (owner, host) first, so the one-active-row
 * invariant holds, then inserts the new row and audits it. Returns the host it
 * authorised, or null if the URL was invalid. Service-role caller only.
 */
export async function recordOffensiveAuthorization(
  supabaseAdmin: SupabaseClient,
  params: { owner: string; authorizedBy: string; targetUrl: string; scope: string; expiresAt?: string | null },
): Promise<{ ok: true; host: string } | { ok: false; reason: "invalid_url" | "unavailable" | "error" }> {
  const host = authHostFromUrl(params.targetUrl);
  if (!host) return { ok: false, reason: "invalid_url" };
  try {
    // Revoke any current active authorization for this target first.
    const revoke = await supabaseAdmin
      .from("offensive_scan_authorizations")
      .update({ revoked_at: new Date().toISOString() })
      .eq("owner", params.owner)
      .eq("target_host", host)
      .is("revoked_at", null);
    if (revoke.error) {
      if (isMissingSchemaError(revoke.error)) return { ok: false, reason: "unavailable" };
      return { ok: false, reason: "error" };
    }
    const insert = await supabaseAdmin.from("offensive_scan_authorizations").insert({
      owner: params.owner,
      target_host: host,
      authorized_by: params.authorizedBy,
      scope: params.scope,
      expires_at: params.expiresAt ?? null,
    });
    if (insert.error) {
      if (isMissingSchemaError(insert.error)) return { ok: false, reason: "unavailable" };
      return { ok: false, reason: "error" };
    }
    await logAuditEvent(supabaseAdmin, {
      actorId: params.authorizedBy,
      action: "offensive_scan.authorized",
      resourceType: "monitored_target",
      resourceId: host,
      metadata: { owner: params.owner, scope: params.scope, expires_at: params.expiresAt ?? null },
    });
    return { ok: true, host };
  } catch {
    return { ok: false, reason: "error" };
  }
}

/** Revoke the active authorization for a target, if any. Audited. */
export async function revokeOffensiveAuthorization(
  supabaseAdmin: SupabaseClient,
  params: { owner: string; actorId: string; targetUrl: string },
): Promise<{ ok: true; host: string } | { ok: false; reason: "invalid_url" | "unavailable" | "error" }> {
  const host = authHostFromUrl(params.targetUrl);
  if (!host) return { ok: false, reason: "invalid_url" };
  try {
    const { error } = await supabaseAdmin
      .from("offensive_scan_authorizations")
      .update({ revoked_at: new Date().toISOString() })
      .eq("owner", params.owner)
      .eq("target_host", host)
      .is("revoked_at", null);
    if (error) {
      if (isMissingSchemaError(error)) return { ok: false, reason: "unavailable" };
      return { ok: false, reason: "error" };
    }
    await logAuditEvent(supabaseAdmin, {
      actorId: params.actorId,
      action: "offensive_scan.revoked",
      resourceType: "monitored_target",
      resourceId: host,
      metadata: { owner: params.owner },
    });
    return { ok: true, host };
  } catch {
    return { ok: false, reason: "error" };
  }
}

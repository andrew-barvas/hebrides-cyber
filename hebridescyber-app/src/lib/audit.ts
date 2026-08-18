// Shared audit-log writer. Before this, audit_logs was written in exactly
// one place in the whole codebase (src/pages/api/stripe/webhook.ts, which
// also (ab)uses it as an idempotency ledger for Stripe event ids) — so the
// admin panel's Audit tab showed billing events and nothing else, for a
// security product where the audit log is one of the first things a
// security-conscious customer checks.
//
// Deliberately best-effort: logging a security event must never be the
// reason the action it's describing fails. Every call site should `await`
// this (so the write actually lands before the response goes out) but never
// let its result gate anything.
import type { SupabaseClient } from "@supabase/supabase-js";

export type AuditEvent = {
  /** Who did this. null for actions with no authenticated actor (e.g. a public share-link view). */
  actorId?: string | null;
  /** Denormalised alongside actorId so the admin UI can search/filter without a join — actor_id can outlive a deleted user, email can't always be re-derived. */
  actorEmail?: string | null;
  /** "<resource>.<verb>" — e.g. "api_key.created", "domain_verification.failed". Keep this vocabulary stable; the admin audit UI's search filters on it. */
  action: string;
  resourceType?: string | null;
  resourceId?: string | null;
  metadata?: Record<string, unknown> | null;
};

export async function logAuditEvent(supabaseAdmin: SupabaseClient, event: AuditEvent): Promise<void> {
  try {
    // Resolved here rather than requiring every call site to look it up —
    // most call sites only have a caller.ownerId (ApiCaller carries no
    // email), and getting this wrong by omission at one call site would
    // silently produce an audit row nobody can attribute to a person.
    let actorEmail = event.actorEmail ?? null;
    if (!actorEmail && event.actorId) {
      const { data } = await supabaseAdmin.from("users").select("email").eq("id", event.actorId).maybeSingle();
      actorEmail = data?.email ?? null;
    }

    const { error } = await supabaseAdmin.from("audit_logs").insert({
      actor: event.actorId ?? null,
      actor_email: actorEmail,
      action: event.action,
      resource_type: event.resourceType ?? null,
      resource_id: event.resourceId ?? null,
      metadata: event.metadata ?? null,
    });
    if (error) console.error(`[audit] failed to log "${event.action}":`, error.message);
  } catch (err) {
    console.error(`[audit] threw while logging "${event.action}":`, (err as Error).message);
  }
}

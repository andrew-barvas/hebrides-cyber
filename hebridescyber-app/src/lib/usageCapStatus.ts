// Shared "how close to a plan cap" classification, used by the admin
// customer-detail view to flag accounts worth an upgrade conversation.
// Pure and synchronously testable, same model as scanCadence.ts's
// isScanDue() — the caller does the Supabase/RPC lookups, this just
// classifies the resulting numbers.

export type CapStatus = "unknown" | "ok" | "near" | "at";

const NEAR_CAP_THRESHOLD = 0.8;

/**
 * `cap === null` means the cap couldn't be determined (e.g. an RPC that
 * errored) — reported as "unknown" rather than guessing ok/at. A `cap` of
 * 0 (no active subscription) is always "at", since `count >= cap` holds
 * for any count >= 0.
 */
export function capStatus(count: number, cap: number | null): CapStatus {
  if (cap === null) return "unknown";
  if (count >= cap) return "at";
  if (cap > 0 && count / cap >= NEAR_CAP_THRESHOLD) return "near";
  return "ok";
}

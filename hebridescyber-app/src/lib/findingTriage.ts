// Finding triage (E-64): a customer's decision about one finding on one site —
// accepted risk (or, for a third-party script, "authorised"), false positive,
// or snoozed until a date — always with a reason. Stored in finding_triage
// (sql/migrations/046_finding_triage.sql), keyed like finding_lifecycle and
// findingsDiff.ts: (owner, target host, checkId). Written only by
// /api/findings/triage; read here.
//
// What each state does (decided once, here, so every consumer agrees):
//   - Every active state moves the finding out of the report's open list and
//     executive-summary counts, out of SLA tracking and SLA alerts
//     (slaMonitoring.ts), and out of the GitHub Action's pass/fail gate.
//   - Only false_positive leaves the score: a later scan scores as if the
//     finding weren't there. An accepted or snoozed risk is still a risk, so
//     it keeps counting. Stored scores are never rewritten.
// A row whose expires_at has passed has no effect at all — the finding is
// simply open again, with its original first-seen date (an expired snooze is
// not a deadline extension).
//
// Pure functions first; the two loaders at the bottom are the only I/O, and
// both treat a missing table (before migration 046) as "nothing triaged".
import type { SupabaseClient } from "@supabase/supabase-js";
import { isMissingSchemaError } from "./dbErrors";
import { hostOf } from "./findingLifecycle";

export const TRIAGE_STATES = ["accepted_risk", "false_positive", "snoozed"] as const;
export type TriageState = (typeof TRIAGE_STATES)[number];

/** UI wording. accepted_risk doubles as "authorised" for third-party script
 *  inventory findings, so its label has to read sensibly for both. */
export const TRIAGE_STATE_LABELS: Record<TriageState, string> = {
  accepted_risk: "Accepted / authorised",
  false_positive: "False positive",
  snoozed: "Snoozed",
};

/** Matches the CHECK in migration 046 (counted in characters, after trimming). */
export const TRIAGE_REASON_MIN = 3;
export const TRIAGE_REASON_MAX = 2000;
/** The longest an expiry may be set into the future. */
export const TRIAGE_MAX_EXPIRY_DAYS = 365;
export const SNOOZE_PRESET_DAYS = [7, 30, 90] as const;
/** Most findings one PUT/DELETE /api/findings/triage request may carry. */
export const TRIAGE_BULK_MAX = 200;

const DAY_MS = 24 * 60 * 60 * 1000;

export const TRIAGE_COLUMNS = "id, owner, target_host, check_id, state, reason, expires_at, created_by, created_at, updated_at";

export type TriageDbRow = {
  id: string;
  owner: string;
  target_host: string;
  check_id: string;
  state: TriageState;
  reason: string;
  expires_at: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
};

/** The per-finding triage summary attached to findings in the dashboard,
 *  the JSON export and the webhook/API report (snake-cased there). */
export type FindingTriage = {
  state: TriageState;
  reason: string;
  expiresAt: string | null;
  triagedAt: string;
};

/** One triage row as /api/findings/triage returns it. `active` is false once
 *  the expiry has passed; `triagedAt` is the last change. */
export type TriageRecord = {
  targetHost: string;
  checkId: string;
  state: TriageState;
  reason: string;
  expiresAt: string | null;
  active: boolean;
  triagedAt: string;
  createdAt: string;
  triagedBy: string | null;
  triagedByEmail: string | null;
};

export function isTriageState(value: unknown): value is TriageState {
  return typeof value === "string" && (TRIAGE_STATES as readonly string[]).includes(value);
}

/** In effect at `now`: no expiry, or an expiry still in the future. An
 *  unparseable expiry counts as expired — a bad row must not hide a finding. */
export function isTriageActive(row: { expires_at: string | null }, now: Date): boolean {
  if (row.expires_at === null) return true;
  const expires = Date.parse(row.expires_at);
  return !Number.isNaN(expires) && expires > now.getTime();
}

/** The row if it's in effect at `now`, otherwise no triage at all. */
export function effectiveTriage<T extends { expires_at: string | null }>(row: T | null | undefined, now: Date): T | null {
  return row && isTriageActive(row, now) ? row : null;
}

/** Hosts are compared the way hostOf() stores them: a bare, lowercased hostname. */
export function normaliseTriageHost(input: string): string | null {
  const value = input.trim();
  if (!value) return null;
  return hostOf(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`);
}

function triageKey(host: string, checkId: string): string {
  return `${host.toLowerCase()} ${checkId}`;
}

/** Active triage rows, looked up by (host, checkId). Built once per request or
 *  scan with a fixed `now`, so one response can't disagree with itself. */
export type TriageIndex = {
  get(host: string, checkId: string | null | undefined): TriageDbRow | undefined;
  readonly size: number;
};

export function buildTriageIndex(rows: TriageDbRow[], now: Date): TriageIndex {
  const map = new Map<string, TriageDbRow>();
  for (const row of rows) {
    if (isTriageState(row.state) && isTriageActive(row, now)) map.set(triageKey(row.target_host, row.check_id), row);
  }
  return {
    get: (host, checkId) => (checkId ? map.get(triageKey(host, checkId)) : undefined),
    get size() {
      return map.size;
    },
  };
}

export const EMPTY_TRIAGE_INDEX: TriageIndex = buildTriageIndex([], new Date(0));

export function toFindingTriage(row: TriageDbRow): FindingTriage {
  return { state: row.state, reason: row.reason, expiresAt: row.expires_at, triagedAt: row.updated_at };
}

/** Each finding with its active triage (or null). Findings without a checkId
 *  can never be triaged — there's nothing stable to key the decision on. */
export function applyTriage<F extends { checkId?: string }>(
  findings: F[],
  host: string,
  index: TriageIndex
): Array<F & { triage: FindingTriage | null }> {
  return findings.map((f) => {
    const row = index.get(host, f.checkId);
    return { ...f, triage: row ? toFindingTriage(row) : null };
  });
}

/** Untriaged findings, and those with an active triage. */
export function partitionByTriage<F extends { checkId?: string }>(
  findings: F[],
  host: string,
  index: TriageIndex
): { open: F[]; triaged: F[] } {
  const open: F[] = [];
  const triaged: F[] = [];
  for (const f of findings) (index.get(host, f.checkId) ? triaged : open).push(f);
  return { open, triaged };
}

/** What the score is computed over: everything except active false positives. */
export function excludeFalsePositives<F extends { checkId?: string }>(findings: F[], host: string, index: TriageIndex): F[] {
  return findings.filter((f) => index.get(host, f.checkId)?.state !== "false_positive");
}

/** Why an expiry is unacceptable, or null if it's fine. `state` decides
 *  whether one is needed at all: a snooze always ends. */
export function expiryProblem(state: TriageState, expiresAt: string | null | undefined, now: Date): string | null {
  if (expiresAt === null || expiresAt === undefined) {
    return state === "snoozed" ? "a snooze needs an expiry date" : null;
  }
  const expires = Date.parse(expiresAt);
  if (Number.isNaN(expires)) return "must be an ISO 8601 date-time";
  if (expires <= now.getTime()) return "must be in the future";
  if (expires > now.getTime() + TRIAGE_MAX_EXPIRY_DAYS * DAY_MS) return `must be within ${TRIAGE_MAX_EXPIRY_DAYS} days`;
  return null;
}

/** Character count as Postgres's char_length sees it (code points, not UTF-16 units). */
export function reasonLength(reason: string): number {
  return Array.from(reason).length;
}

export type TriageLoad = { rows: TriageDbRow[]; available: boolean; error: string | null };

async function loadTriage(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  host: string | null
): Promise<TriageLoad> {
  try {
    let query = supabaseAdmin.from("finding_triage").select(TRIAGE_COLUMNS).eq("owner", ownerId);
    if (host) query = query.eq("target_host", host);
    const { data, error } = await query;
    if (error) {
      if (isMissingSchemaError(error)) return { rows: [], available: false, error: null };
      return { rows: [], available: true, error: error.message };
    }
    return { rows: ((data ?? []) as TriageDbRow[]).filter((r) => isTriageState(r.state)), available: true, error: null };
  } catch (err) {
    return { rows: [], available: true, error: (err as Error).message };
  }
}

/** One site's triage rows (active or not). Never throws: before migration 046
 *  it reports `available: false` with no rows; any other failure comes back
 *  in `error` so the caller decides whether that's fatal. */
export function loadTriageForHost(supabaseAdmin: SupabaseClient, ownerId: string, host: string): Promise<TriageLoad> {
  return loadTriage(supabaseAdmin, ownerId, host.toLowerCase());
}

/** Every triage row on the account — for cross-site views like SLAs. */
export function loadTriageForOwner(supabaseAdmin: SupabaseClient, ownerId: string): Promise<TriageLoad> {
  return loadTriage(supabaseAdmin, ownerId, null);
}

/**
 * Active triage for one site as an index, for callers where triage is an
 * enhancement rather than the point (scan scoring, reports, exports): any
 * failure — table missing, query error — degrades to "nothing triaged".
 */
export async function loadTriageIndexForTarget(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  targetUrl: string,
  now: Date = new Date()
): Promise<{ host: string | null; index: TriageIndex }> {
  const host = hostOf(targetUrl);
  if (!host) return { host: null, index: EMPTY_TRIAGE_INDEX };
  const loaded = await loadTriageForHost(supabaseAdmin, ownerId, host);
  if (loaded.error) console.error(`[findingTriage] load failed for ${host}:`, loaded.error);
  return { host, index: buildTriageIndex(loaded.rows, now) };
}

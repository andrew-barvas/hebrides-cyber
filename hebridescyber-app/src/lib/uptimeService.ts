// Server-side logic for the bring-your-own-account uptime offering: connecting
// the customer's provider account, creating monitors for their verified
// targets, and syncing statuses. The decisions are pure functions
// (decideUptimeAlert, planSync) so they are tested without a database; the
// functions that touch Supabase take the client and the provider as arguments.
//
// Evidence rules (CLAUDE.md rule 7): a provider call that fails changes
// nothing. A stored status is never overwritten with a guess, a monitor the
// provider no longer lists is reported as missing rather than "up", and an
// alert is only ever raised on a clear "down".
import type { SupabaseClient } from "@supabase/supabase-js";
import { revealSecrets } from "./credentialEncryption";
import { hostnameFromUrl, isDomainVerified } from "./ownership";
import { normaliseMonitorUrl, type ProviderErrorKind, type UptimeMonitor, type UptimeProvider, type UptimeStatus } from "./uptimeProvider";
import { uptimeRobotProvider } from "./uptimeRobot";

export type UptimeAlertKind = "down" | "recovered";

/**
 * One "down" message per outage and one "recovered" message when it ends.
 * `alerted` is whether the current outage has already been announced; only a
 * clear "down" opens an outage, and only a clear "up" closes one. seems_down,
 * paused and unknown change nothing, so a flapping check can't spam.
 */
export function decideUptimeAlert(alerted: boolean, next: UptimeStatus): UptimeAlertKind | null {
  if (next === "down" && !alerted) return "down";
  if (next === "up" && alerted) return "recovered";
  return null;
}

export type StoredUptimeMonitor = {
  id: string;
  target_url: string;
  external_id: string;
  last_status: UptimeStatus | null;
  last_status_at: string | null;
  down_alerted_at: string | null;
};

export type MonitorUpdate = {
  id: string;
  last_status: UptimeStatus;
  last_status_at: string;
  state_duration_seconds: number | null;
  last_checked_at: string;
  down_alerted_at: string | null;
};

export type PlannedAlert = {
  kind: UptimeAlertKind;
  targetUrl: string;
  monitorId: string;
  /** down_alerted_at as this sync read it; the update only lands (and the alert only goes) if it is unchanged. */
  previousDownAlertedAt: string | null;
};

export type SyncPlan = {
  updates: MonitorUpdate[];
  alerts: PlannedAlert[];
  /** Stored monitors the provider no longer lists (deleted on their side). Left untouched. */
  missing: string[];
};

/** Reconcile stored rows with what the provider lists. Pure. */
export function planSync(stored: StoredUptimeMonitor[], live: UptimeMonitor[], now: Date): SyncPlan {
  const byId = new Map(live.map((m) => [m.externalId, m]));
  const plan: SyncPlan = { updates: [], alerts: [], missing: [] };
  const iso = now.toISOString();
  for (const row of stored) {
    const monitor = byId.get(row.external_id);
    if (!monitor) {
      plan.missing.push(row.target_url);
      continue;
    }
    const alert = decideUptimeAlert(Boolean(row.down_alerted_at), monitor.status);
    if (alert) plan.alerts.push({ kind: alert, targetUrl: row.target_url, monitorId: row.id, previousDownAlertedAt: row.down_alerted_at });
    plan.updates.push({
      id: row.id,
      last_status: monitor.status,
      last_status_at: row.last_status === monitor.status && row.last_status_at ? row.last_status_at : iso,
      state_duration_seconds: monitor.stateDurationSeconds,
      last_checked_at: iso,
      down_alerted_at: alert === "down" ? iso : alert === "recovered" ? null : row.down_alerted_at,
    });
  }
  return plan;
}

export type IntegrationLookup =
  | { status: "none" }
  | { status: "undecryptable" }
  | { status: "ok"; id: string; provider: UptimeProvider; lastSyncAt: string | null };

/** Load the owner's connection and build a provider for it. Never exposes the key. */
export async function loadUptimeProvider(db: SupabaseClient, ownerId: string): Promise<IntegrationLookup | { status: "error"; error: string }> {
  const { data, error } = await db
    .from("uptime_integrations")
    .select("id, provider, api_key, last_sync_at")
    .eq("owner", ownerId)
    .eq("provider", "uptimerobot")
    .maybeSingle();
  if (error) return { status: "error", error: error.message };
  if (!data) return { status: "none" };
  const revealed = revealSecrets(data as { api_key: string }, ["api_key"]);
  if (!revealed) return { status: "undecryptable" };
  return { status: "ok", id: data.id as string, provider: uptimeRobotProvider(revealed.api_key), lastSyncAt: (data.last_sync_at as string | null) ?? null };
}

export type SyncOutcome =
  | { ok: true; alerts: SyncPlan["alerts"]; missing: string[]; updated: number }
  | { ok: false; kind: ProviderErrorKind | "database"; error: string; retryAfterSeconds?: number };

/**
 * Refresh one owner's stored monitors from the provider. A provider failure
 * records `last_error` on the connection and leaves every stored status as it
 * was; a database failure is reported, not swallowed.
 */
export async function syncOwnerMonitors(db: SupabaseClient, ownerId: string, integrationId: string, provider: UptimeProvider, now: Date = new Date()): Promise<SyncOutcome> {
  const { data: rows, error: rowsError } = await db
    .from("uptime_monitors")
    .select("id, target_url, external_id, last_status, last_status_at, down_alerted_at")
    .eq("owner", ownerId)
    .eq("provider", provider.id);
  if (rowsError) return { ok: false, kind: "database", error: rowsError.message };
  const stored = (rows ?? []) as StoredUptimeMonitor[];

  const live = await provider.listMonitors();
  if (!live.ok) {
    await db.from("uptime_integrations").update({ last_error: live.error.slice(0, 500), updated_at: now.toISOString() }).eq("id", integrationId);
    return { ok: false, kind: live.kind, error: live.error, retryAfterSeconds: live.retryAfterSeconds };
  }

  const plan = planSync(stored, live.value, now);
  const alertFor = new Map(plan.alerts.map((a) => [a.monitorId, a]));
  const alerts: PlannedAlert[] = [];
  for (const { id, ...patch } of plan.updates) {
    const alert = alertFor.get(id);
    if (!alert) {
      const { error } = await db.from("uptime_monitors").update(patch).eq("id", id);
      if (error) return { ok: false, kind: "database", error: error.message };
      continue;
    }
    // Compare-and-set on the outage marker. The cron and a dashboard refresh
    // can sync the same owner at the same moment; only the one whose write
    // lands sends the message, so an outage is announced once.
    const update = db.from("uptime_monitors").update(patch).eq("id", id);
    const guarded = alert.previousDownAlertedAt === null ? update.is("down_alerted_at", null) : update.eq("down_alerted_at", alert.previousDownAlertedAt);
    const { data, error } = await guarded.select("id");
    if (error) return { ok: false, kind: "database", error: error.message };
    if ((data ?? []).length > 0) alerts.push(alert);
  }
  await db.from("uptime_integrations").update({ last_sync_at: now.toISOString(), last_error: null, updated_at: now.toISOString() }).eq("id", integrationId);
  return { ok: true, alerts, missing: plan.missing, updated: plan.updates.length };
}

export type SyncAllSummary = { synced: number; failed: number; lapsed: number; alerts: number };

/**
 * The cron's loop (sync-uptime-monitors.ts): every connected owner, one at a
 * time. Owners whose plan no longer includes uptime monitoring are skipped:
 * the dashboard and routes stop serving it when a subscription lapses, and so
 * must the background sync and its messages. One owner's failure never stops
 * the others.
 */
export async function syncAllOwners(
  db: SupabaseClient,
  deps: {
    gate: (db: SupabaseClient, ownerId: string) => Promise<"ok" | "denied" | "error">;
    sendAlert: (db: SupabaseClient, ownerId: string, kind: UptimeAlertKind, targetUrl: string) => Promise<void>;
    log?: (message: string) => void;
  },
): Promise<{ ok: true; summary: SyncAllSummary } | { ok: false; error: string }> {
  const log = deps.log ?? (() => {});
  const { data: owners, error } = await db.from("uptime_integrations").select("owner").eq("provider", "uptimerobot");
  if (error) return { ok: false, error: error.message };

  const summary: SyncAllSummary = { synced: 0, failed: 0, lapsed: 0, alerts: 0 };
  for (const { owner } of (owners ?? []) as Array<{ owner: string }>) {
    const gate = await deps.gate(db, owner);
    if (gate === "denied") {
      summary.lapsed++;
      continue;
    }
    if (gate === "error") {
      log(`owner ${owner}: could not check plan`);
      summary.failed++;
      continue;
    }
    const integration = await loadUptimeProvider(db, owner);
    if (integration.status !== "ok") {
      log(`owner ${owner}: ${integration.status}`);
      summary.failed++;
      continue;
    }
    const outcome = await syncOwnerMonitors(db, owner, integration.id, integration.provider);
    if (!outcome.ok) {
      log(`owner ${owner}: sync failed (${outcome.kind}): ${outcome.error}`);
      summary.failed++;
      continue;
    }
    summary.synced++;
    for (const alert of outcome.alerts) {
      await deps.sendAlert(db, owner, alert.kind, alert.targetUrl);
      summary.alerts++;
    }
  }
  return { ok: true, summary };
}

export type CreateOutcome =
  | { targetUrl: string; result: "created" | "adopted" | "exists" }
  | { targetUrl: string; result: "not_monitored" | "not_verified" | "invalid_url" | "skipped" }
  | { targetUrl: string; result: "error"; kind: ProviderErrorKind | "database"; error: string };

/** Targets one call may create monitors for: each costs a provider request and the free plan allows 10 a minute. */
export const MAX_MONITORS_PER_REQUEST = 8;

/**
 * Create (or adopt) a monitor for each requested target. Only targets the owner
 * monitors AND has verified are eligible, so a customer's key is never used to
 * watch a site they haven't proven they control. Stops at the first auth or
 * rate-limit failure and marks the rest `skipped`.
 */
export async function createMonitorsForTargets(db: SupabaseClient, ownerId: string, provider: UptimeProvider, targetUrls: string[]): Promise<CreateOutcome[]> {
  const [{ data: targetRows, error: targetsError }, { data: existingRows, error: existingError }] = await Promise.all([
    db.from("monitored_targets").select("target_url").eq("owner", ownerId),
    db.from("uptime_monitors").select("target_url").eq("owner", ownerId).eq("provider", provider.id),
  ]);
  // Without these we can't tell "not one of your sites" or "already monitored"
  // from a failed read, so say it failed rather than guess either way.
  const readError = targetsError ?? existingError;
  if (readError) return targetUrls.map((targetUrl) => ({ targetUrl, result: "error", kind: "database", error: readError.message }));

  const monitored = new Map<string, string>();
  for (const r of (targetRows ?? []) as Array<{ target_url: string }>) {
    const key = normaliseMonitorUrl(r.target_url);
    if (key) monitored.set(key, r.target_url);
  }
  const existing = new Set(((existingRows ?? []) as Array<{ target_url: string }>).map((r) => normaliseMonitorUrl(r.target_url)));

  let liveByUrl: Map<string, UptimeMonitor> | null = null;
  let halted: { kind: ProviderErrorKind } | null = null;
  const out: CreateOutcome[] = [];

  for (const requested of targetUrls.slice(0, MAX_MONITORS_PER_REQUEST)) {
    const key = normaliseMonitorUrl(requested);
    if (!key) {
      out.push({ targetUrl: requested, result: "invalid_url" });
      continue;
    }
    const stored = monitored.get(key);
    if (!stored) {
      out.push({ targetUrl: requested, result: "not_monitored" });
      continue;
    }
    if (existing.has(key)) {
      out.push({ targetUrl: stored, result: "exists" });
      continue;
    }
    if (!(await isDomainVerified(db, ownerId, stored))) {
      out.push({ targetUrl: stored, result: "not_verified" });
      continue;
    }
    if (halted) {
      out.push({ targetUrl: stored, result: "skipped" });
      continue;
    }

    if (!liveByUrl) {
      const listed = await provider.listMonitors();
      if (!listed.ok) {
        halted = { kind: listed.kind };
        out.push({ targetUrl: stored, result: "error", kind: listed.kind, error: listed.error });
        continue;
      }
      liveByUrl = new Map();
      for (const m of listed.value) {
        const k = m.url ? normaliseMonitorUrl(m.url) : null;
        if (k) liveByUrl.set(k, m);
      }
    }

    let monitor = liveByUrl.get(key);
    const adopted = Boolean(monitor);
    if (!monitor) {
      const created = await provider.createMonitor({ url: stored, name: `Hebrides: ${hostnameFromUrl(stored)}` });
      if (!created.ok) {
        if (created.kind === "auth" || created.kind === "rate_limited") halted = { kind: created.kind };
        out.push({ targetUrl: stored, result: "error", kind: created.kind, error: created.error });
        continue;
      }
      monitor = created.value;
    }

    const { error } = await db.from("uptime_monitors").insert({
      owner: ownerId,
      target_url: stored,
      provider: provider.id,
      external_id: monitor.externalId,
      last_status: monitor.status,
      last_status_at: new Date().toISOString(),
      state_duration_seconds: monitor.stateDurationSeconds,
      last_checked_at: new Date().toISOString(),
    });
    if (error) {
      out.push({ targetUrl: stored, result: "error", kind: "database", error: error.message });
      continue;
    }
    existing.add(key);
    out.push({ targetUrl: stored, result: adopted ? "adopted" : "created" });
  }

  for (const requested of targetUrls.slice(MAX_MONITORS_PER_REQUEST)) out.push({ targetUrl: requested, result: "skipped" });
  return out;
}

// GET /api/uptime/status — the uptime card's data: whether the owner has
// connected UptimeRobot, the cached status of each monitor, and which of their
// monitored targets still have no monitor. Refreshes from UptimeRobot when the
// cache is older than five minutes (and the per-owner limit allows), because
// the free UptimeRobot API allows only 10 requests a minute. A refresh that
// fails returns the cached rows plus `refreshError`; it never invents a status.
import type { NextApiRequest, NextApiResponse } from "next";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { planGate } from "@/lib/planAccess";
import { checkRateLimit } from "@/lib/rateLimit";
import { sendUptimeAlert } from "@/lib/uptimeAlerts";
import { loadUptimeProvider, syncOwnerMonitors } from "@/lib/uptimeService";
import { normaliseMonitorUrl } from "@/lib/uptimeProvider";

const STALE_AFTER_MS = 5 * 60 * 1000;

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") return res.status(403).json({ error: "Uptime status is available from a logged-in session only." });

  const gate = await planGate(supabaseAdmin, caller.ownerId, "pro");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan — try again." });
  if (gate === "denied") return res.status(200).json({ allowed: false, connected: false, monitors: [], unmonitored: [] });

  const integration = await loadUptimeProvider(supabaseAdmin, caller.ownerId);
  if (integration.status === "error") return res.status(500).json({ error: "Could not load your uptime connection." });
  if (integration.status === "none") return res.status(200).json({ allowed: true, connected: false, monitors: [], unmonitored: [] });

  let refreshError: string | undefined;
  if (integration.status === "undecryptable") {
    refreshError = "Your saved UptimeRobot key can no longer be read. Disconnect and connect it again.";
  } else {
    const stale = !integration.lastSyncAt || Date.now() - new Date(integration.lastSyncAt).getTime() > STALE_AFTER_MS;
    if (stale) {
      const limit = await checkRateLimit(caller.ownerId, "uptime-sync", { max: 30, windowSeconds: 60 * 60 });
      if (limit.allowed) {
        const outcome = await syncOwnerMonitors(supabaseAdmin, caller.ownerId, integration.id, integration.provider);
        if (outcome.ok) {
          for (const alert of outcome.alerts) await sendUptimeAlert(supabaseAdmin, caller.ownerId, alert.kind, alert.targetUrl);
        } else {
          refreshError = outcome.error;
        }
      }
    }
  }

  const [{ data: monitorRows }, { data: targetRows }, { data: fresh }] = await Promise.all([
    supabaseAdmin
      .from("uptime_monitors")
      .select("target_url, last_status, last_status_at, state_duration_seconds, last_checked_at")
      .eq("owner", caller.ownerId)
      .eq("provider", "uptimerobot")
      .order("target_url"),
    supabaseAdmin.from("monitored_targets").select("target_url").eq("owner", caller.ownerId),
    supabaseAdmin.from("uptime_integrations").select("last_sync_at, last_error").eq("owner", caller.ownerId).eq("provider", "uptimerobot").maybeSingle(),
  ]);

  // A sync stamps last_checked_at on every monitor UptimeRobot still lists with
  // the same time it stamps last_sync_at, so a row checked before the last
  // successful sync is one UptimeRobot no longer has (deleted on their side).
  // Its stored status is stale, and the card must say so rather than show it as current.
  const lastSync = fresh?.last_sync_at ? Date.parse(fresh.last_sync_at as string) : NaN;
  const monitors = ((monitorRows ?? []) as Array<{ target_url: string; last_checked_at: string | null }>).map((m) => ({
    ...m,
    missing: Number.isFinite(lastSync) && m.last_checked_at !== null && Date.parse(m.last_checked_at) < lastSync,
  }));
  const covered = new Set(monitors.map((m) => normaliseMonitorUrl(m.target_url)));
  const unmonitored = ((targetRows ?? []) as Array<{ target_url: string }>).map((t) => t.target_url).filter((u) => !covered.has(normaliseMonitorUrl(u)));

  return res.status(200).json({
    allowed: true,
    connected: true,
    lastSyncAt: fresh?.last_sync_at ?? null,
    lastError: fresh?.last_error ?? null,
    refreshError,
    monitors,
    unmonitored,
  });
}

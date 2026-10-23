// Refreshes every connected UptimeRobot account's monitor statuses and sends
// one down / recovered message per outage. Run by
// .github/workflows/uptime-sync.yml every 15 minutes.
//
// Without this the dashboard would only learn about an outage when the
// customer next opened it. Each owner costs one UptimeRobot list request
// (their own account's quota), and a provider failure for one owner never
// stops the others or changes any stored status.
//
// Run locally with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... CREDENTIALS_ENC_KEY=... npx tsx src/scripts/sync-uptime-monitors.ts
import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import { sendUptimeAlert } from "../lib/uptimeAlerts";
import { loadUptimeProvider, syncOwnerMonitors } from "../lib/uptimeService";

async function main() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }
  const db = createClient(supabaseUrl, serviceRoleKey, { realtime: { transport: ws as unknown as WebSocketLikeConstructor } });

  const { data: owners, error } = await db.from("uptime_integrations").select("owner").eq("provider", "uptimerobot");
  if (error) {
    console.error("Failed to list uptime integrations:", error.message);
    process.exit(1);
  }

  let synced = 0;
  let failed = 0;
  let alerts = 0;
  for (const { owner } of (owners ?? []) as Array<{ owner: string }>) {
    const integration = await loadUptimeProvider(db, owner);
    if (integration.status !== "ok") {
      console.warn(`[uptime] owner ${owner}: ${integration.status}`);
      failed++;
      continue;
    }
    const outcome = await syncOwnerMonitors(db, owner, integration.id, integration.provider);
    if (!outcome.ok) {
      console.warn(`[uptime] owner ${owner}: sync failed (${outcome.kind}): ${outcome.error}`);
      failed++;
      continue;
    }
    synced++;
    for (const alert of outcome.alerts) {
      await sendUptimeAlert(db, owner, alert.kind, alert.targetUrl);
      alerts++;
    }
  }
  console.log(`[uptime] synced ${synced}, failed ${failed}, alerts sent ${alerts}.`);
}

main().catch((err) => {
  console.error("sync-uptime-monitors failed:", err);
  process.exit(1);
});

// Refreshes every connected UptimeRobot account's monitor statuses and sends
// one down / recovered message per outage. Run by
// .github/workflows/uptime-sync.yml every 15 minutes.
//
// Without this the dashboard would only learn about an outage when the
// customer next opened it. Each owner costs one UptimeRobot list request
// (their own account's quota), and a provider failure for one owner never
// stops the others or changes any stored status. Owners whose subscription no
// longer includes uptime monitoring are skipped (uptimeService.ts's
// syncAllOwners holds the loop).
//
// Run locally with:
//   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... CREDENTIALS_ENC_KEY=... npx tsx src/scripts/sync-uptime-monitors.ts
import { createClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";
import { planGate } from "../lib/planAccess";
import { sendUptimeAlert } from "../lib/uptimeAlerts";
import { syncAllOwners } from "../lib/uptimeService";

async function main() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceRoleKey) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }
  const db = createClient(supabaseUrl, serviceRoleKey, { realtime: { transport: ws as unknown as WebSocketLikeConstructor } });

  const result = await syncAllOwners(db, {
    gate: (client, owner) => planGate(client, owner, "pro"),
    sendAlert: sendUptimeAlert,
    log: (message) => console.warn(`[uptime] ${message}`),
  });
  if (!result.ok) {
    console.error("Failed to list uptime integrations:", result.error);
    process.exit(1);
  }
  const { synced, failed, lapsed, alerts } = result.summary;
  console.log(`[uptime] synced ${synced}, failed ${failed}, skipped ${lapsed} (plan lapsed), alerts sent ${alerts}.`);
}

main().catch((err) => {
  console.error("sync-uptime-monitors failed:", err);
  process.exit(1);
});

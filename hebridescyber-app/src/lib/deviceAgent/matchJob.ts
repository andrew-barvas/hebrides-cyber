// The device matching job: for each active device whose latest report is
// newer than its last match, match the report (matching.ts), re-evaluate the
// 14-day rule (patchRule.ts) and store both on the device.
//
// Run by src/scripts/match-device-inventories.ts from
// .github/workflows/device-inventory-match.yml, never from an HTTP request:
// OSV.dev and the CVE index reads take longer than a Functions request
// should. Before migration 086 it reports "unavailable" and does nothing.
import type { SupabaseClient } from "@supabase/supabase-js";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { inventorySchema } from "./inventorySchema";
import { evaluatePatchRule } from "./patchRule";
import { matchInventory, type MatchDeps } from "./matching";

export const MATCH_BATCH = 100;

export type MatchJobResult =
  | { status: "unavailable" }
  | { status: "done"; matched: number; skipped: number; errors: string[] };

type QueueRow = { id: string; owner: string; last_seen_at: string; matched_at: string | null; pending_first_seen: unknown };

/** Pure: the devices whose report hasn't been matched since it arrived. */
export function needsMatch(row: Pick<QueueRow, "last_seen_at" | "matched_at">): boolean {
  return !row.matched_at || Date.parse(row.matched_at) < Date.parse(row.last_seen_at);
}

export async function runDeviceMatchJob(
  db: SupabaseClient,
  makeDeps: () => Promise<MatchDeps>,
  options: { limit?: number; dryRun?: boolean } = {}
): Promise<MatchJobResult> {
  const { data, error } = await db
    .from("agent_devices")
    .select("id, owner, last_seen_at, matched_at, pending_first_seen")
    .is("revoked_at", null)
    .not("last_seen_at", "is", null)
    .order("last_seen_at", { ascending: true })
    .limit(1000);
  if (error) {
    if (isMissingSchemaError(error)) return { status: "unavailable" };
    throw new Error(`reading agent_devices: ${error.message}`);
  }
  const queue = ((data ?? []) as QueueRow[]).filter(needsMatch).slice(0, options.limit ?? MATCH_BATCH);
  const errors: string[] = [];
  let matched = 0;
  let skipped = 0;
  if (queue.length === 0) return { status: "done", matched, skipped, errors };

  const deps = await makeDeps();
  for (const device of queue) {
    try {
      const { data: inv, error: invError } = await db
        .from("agent_inventories")
        .select("inventory, received_at")
        .eq("device_id", device.id)
        .order("received_at", { ascending: false })
        .limit(1)
        .maybeSingle();
      if (invError) throw new Error(invError.message);
      const parsed = inventorySchema.safeParse(inv?.inventory);
      if (!inv || !parsed.success) {
        skipped++;
        continue;
      }
      const now = deps.now;
      const match = await matchInventory(parsed.data, deps);
      // The first-seen map is re-derived from the stored one, not advanced:
      // the inventory route owns it, and this report's updates are already in it.
      const firstSeen = device.pending_first_seen && typeof device.pending_first_seen === "object" ? (device.pending_first_seen as Record<string, string>) : {};
      const { pendingFirstSeen, ...evaluation } = evaluatePatchRule({ inventory: parsed.data, previousFirstSeen: firstSeen, match, now });
      void pendingFirstSeen;
      if (options.dryRun) {
        matched++;
        continue;
      }
      const { error: updateError } = await db
        .from("agent_devices")
        .update({ last_match: match, matched_at: now.toISOString(), patch_status: evaluation.status, evaluation })
        .eq("id", device.id)
        // Only if no newer report landed meanwhile; the next run picks that up.
        .eq("last_seen_at", device.last_seen_at);
      if (updateError) throw new Error(updateError.message);
      matched++;
    } catch (err) {
      errors.push(`device ${device.id}: ${(err as Error).message}`);
    }
  }
  return { status: "done", matched, skipped, errors };
}

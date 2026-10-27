// Server-side: turn a client scope (a client id, or "unassigned") into the set
// of site hostnames it covers, so cross-site endpoints (findings, SLA, v1
// scans) can filter by client. Sites are matched by hostname, the same
// convention as findingLifecycle / FleetOverview. Always owner-scoped, so a
// client id belonging to another account resolves to "not found".
import type { SupabaseClient } from "@supabase/supabase-js";
import { isMissingSchemaError } from "./dbErrors";
import { hostOf } from "./findingLifecycle";

export type ClientScopeResult =
  | { ok: true; hosts: Set<string>; urls: string[] }
  | { ok: false; status: 404 | 500 | 503; error: string };

/** First value of a query param, trimmed; null when absent or blank. */
export function clientParam(value: string | string[] | undefined): string | null {
  const v = (Array.isArray(value) ? value[0] : value)?.trim();
  return v ? v : null;
}

export async function resolveClientScope(db: SupabaseClient, ownerId: string, scope: string): Promise<ClientScopeResult> {
  if (scope !== "unassigned") {
    const { data, error } = await db.from("clients").select("id").eq("id", scope).eq("owner", ownerId).maybeSingle();
    if (error) {
      return isMissingSchemaError(error)
        ? { ok: false, status: 503, error: "Client workspaces aren't enabled on this server yet (database migration 064 pending)." }
        : { ok: false, status: 500, error: "Could not resolve the client" };
    }
    if (!data) return { ok: false, status: 404, error: "Client not found" };
  }

  let query = db.from("monitored_targets").select("target_url").eq("owner", ownerId);
  query = scope === "unassigned" ? query.is("client_id", null) : query.eq("client_id", scope);
  const { data, error } = await query;
  if (error) {
    return isMissingSchemaError(error)
      ? { ok: false, status: 503, error: "Client workspaces aren't enabled on this server yet (database migration 064 pending)." }
      : { ok: false, status: 500, error: "Could not resolve the client's sites" };
  }

  const urls = ((data ?? []) as { target_url: string }[]).map((t) => t.target_url);
  const hosts = new Set<string>();
  for (const u of urls) {
    const h = hostOf(u);
    if (h) hosts.add(h);
  }
  return { ok: true, hosts, urls };
}

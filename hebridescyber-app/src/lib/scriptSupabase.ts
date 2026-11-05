// Service-role Supabase client for the CLI/cron entry points in src/scripts/.
//
// Every script used to repeat the same eight lines: read SUPABASE_URL and
// SUPABASE_SERVICE_ROLE_KEY, print an error and exit 1 when either is
// missing, then build a client with `ws` as the realtime transport.
// createClient() constructs a RealtimeClient unconditionally, even for a
// script that never subscribes, and the Node 20 CI runners have no global
// WebSocket for it to use.
// Fourteen copies drifted in wording and option shape; this is the one copy.
//
// API routes use supabaseAdmin.ts instead — it throws rather than exiting,
// because a route must answer the request, not kill the process.
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { WebSocketLikeConstructor } from "@supabase/realtime-js";
import ws from "ws";

/**
 * Reads the service-role env vars and returns a client, or fails fast:
 * prints which variables are missing and exits 1 before any work starts.
 */
export function createScriptSupabase(env: Record<string, string | undefined> = process.env): SupabaseClient {
  const url = env.SUPABASE_URL;
  const key = env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.");
    process.exit(1);
  }
  return createClient(url, key, {
    realtime: { transport: ws as unknown as WebSocketLikeConstructor },
  });
}

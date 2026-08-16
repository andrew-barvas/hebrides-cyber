// Canonical service-role Supabase client for API routes (src/pages/api/**).
//
// Built lazily, not at module import. @supabase/supabase-js's createClient()
// throws synchronously if the URL is empty — constructing it at module scope
// means a missing SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY turns *every* request
// to that route file into an unhandled exception (a Next.js error page with a
// stack trace), including requests that should simply have been rejected with
// a clean 401/403 before any Supabase call was needed.
//
// Every route should import `supabaseAdmin` from here rather than constructing
// its own client — one lazy client, reused everywhere, instead of the same
// fragile pattern repeated per file.
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

let client: SupabaseClient | null = null;

export function getSupabaseAdmin(): SupabaseClient {
  if (client) return client;
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) {
    throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set");
  }
  client = createClient(url, key);
  return client;
}

/** Proxy so callers can keep importing `supabaseAdmin` as a plain value. */
export const supabaseAdmin = new Proxy({} as SupabaseClient, {
  get(_target, prop) {
    return Reflect.get(getSupabaseAdmin(), prop);
  },
});

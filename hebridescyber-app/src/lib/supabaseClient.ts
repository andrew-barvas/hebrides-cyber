import { createClient } from "@supabase/supabase-js";

// Browser-safe Supabase client. Uses the public URL + anon key, which are
// intended to be exposed client-side — RLS policies (see
// sql/migrations/001_init.sql) are what actually protect the data.
//
// TODO: once you have a real Supabase project, copy its URL and anon key
// into .env.local (see .env.example).
const envUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const envAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

// @supabase/supabase-js's createClient() THROWS synchronously if either
// argument is empty (it validates the URL, not just warns) — that crashes
// every page that imports this module (dashboard, login, blog, pricing...)
// the moment Next.js server-renders them, even before any Supabase call is
// actually made. Fall back to a well-formed placeholder so the app still
// boots without a configured project; auth/data calls will simply fail at
// call time instead, which is the earlier, more debuggable behaviour the
// warning below is describing.
const supabaseUrl = envUrl || "https://placeholder.supabase.co";
const supabaseAnonKey = envAnonKey || "placeholder-anon-key";

if (!envUrl || !envAnonKey) {
  console.warn(
    "[supabaseClient] NEXT_PUBLIC_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_ANON_KEY " +
      "are not set — using a placeholder client. Auth and data features will not " +
      "work until you set them in .env.local (see .env.example)."
  );
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

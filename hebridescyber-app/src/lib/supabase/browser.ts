// E-21: cookie-based browser Supabase client — replaces the localStorage-
// backed createClient() with @supabase/ssr's createBrowserClient(), which
// stores session tokens in cookies instead of localStorage. Cookies are
// SameSite=Lax + Secure (in production), scoped to the domain, and
// readable server-side by the middleware and API routes.
import { createBrowserClient } from "@supabase/ssr";

const envUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const envAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

const supabaseUrl = envUrl || "https://placeholder.supabase.co";
const supabaseAnonKey = envAnonKey || "placeholder-anon-key";

if (typeof window !== "undefined" && (!envUrl || !envAnonKey)) {
  console.warn(
    "[supabase/browser] NEXT_PUBLIC_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_ANON_KEY " +
      "are not set — using a placeholder client. Auth and data features will not " +
      "work until you set them in .env.local (see .env.example)."
  );
}

export const supabase = createBrowserClient(supabaseUrl, supabaseAnonKey);

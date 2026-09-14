// E-21: re-exports the cookie-based browser client so every existing
// `import { supabase } from "@/lib/supabaseClient"` picks up the SSR-
// aware client without a mass find-and-replace. Session tokens are now
// stored in cookies (SameSite=Lax, Secure in production) instead of
// localStorage — readable server-side by middleware and API routes.
export { supabase } from "./supabase/browser";

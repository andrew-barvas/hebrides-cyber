// E-21: server-side auth callback — exchanges the OAuth/magic-link ?code=
// for a session server-side so the tokens are set as cookies by the server,
// not by client-side JS. This replaces the client-side exchangeCodeForSession
// that stored tokens in localStorage.
import { NextResponse } from "next/server";
import { createServerSupabaseClient } from "@/lib/supabase/server";
import { safeNextPath } from "@/lib/safeRedirect";

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get("code");
  // Only a path on this site: `${origin}${next}` with "@evil.example" would leave it.
  const next = safeNextPath(searchParams.get("next"));

  if (code) {
    const supabase = await createServerSupabaseClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) {
      return NextResponse.redirect(`${origin}${next}`);
    }
  }

  return NextResponse.redirect(`${origin}/login?error=auth_callback_failed`);
}

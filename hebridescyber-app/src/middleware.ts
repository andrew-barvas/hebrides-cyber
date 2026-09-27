// E-21: server-side auth protection via @supabase/ssr cookies.
// Refreshes the session on every matched request and redirects to /login
// if the session is missing or expired. Protected routes no longer depend
// solely on client-side getSession() checks.
//
// /login must never be in the matcher: a signed-out visitor loading it would
// be redirected to /login, match again, and loop forever — nobody could sign
// in. Login brute-force protection doesn't belong here either: credentials go
// from the browser straight to Supabase Auth (src/lib/auth.ts), which
// rate-limits its own endpoints, so a POST /login limiter here would guard
// nothing. tests/e2e/dashboard.spec.ts covers both halves of this.
import { type NextRequest, NextResponse } from "next/server";
import { createMiddlewareClient } from "@/lib/supabase/middleware";

export async function middleware(req: NextRequest) {
  const { supabase, response } = createMiddlewareClient(req);

  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    const loginUrl = req.nextUrl.clone();
    loginUrl.pathname = "/login";
    loginUrl.searchParams.set("redirect", req.nextUrl.pathname);
    return NextResponse.redirect(loginUrl);
  }

  return response;
}

export const config = {
  matcher: ["/dashboard/:path*", "/admin/:path*", "/account/:path*"],
};

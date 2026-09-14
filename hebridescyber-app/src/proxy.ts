// E-21: server-side auth protection via @supabase/ssr cookies.
// Refreshes the session on every matched request and redirects to /login
// if the session is missing or expired. Protected routes no longer depend
// solely on client-side getSession() checks.
import { type NextRequest, NextResponse } from "next/server";
import { createMiddlewareClient } from "@/lib/supabase/middleware";

export async function proxy(req: NextRequest) {
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

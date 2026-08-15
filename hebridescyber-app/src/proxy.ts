// Server-side auth guard (Next.js 16 proxy = middleware).
// Redirects unauthenticated users away from /dashboard and /admin
// before the page component even renders — prevents the client-side
// auth flash and is the only path that actually secures server-rendered
// content.
//
// Note: Supabase session cookies are httpOnly, so we check for the presence
// of the sb-* cookie that Supabase sets on successful auth. This is a
// lightweight heuristic — the actual token is re-validated server-side in
// each API route via supabaseAdmin.auth.getUser(). Cookie presence here
// only prevents the redirect loop for already-authed users; it does not
// grant any privileges.

import { type NextRequest, NextResponse } from "next/server";

const PROTECTED_PREFIXES = ["/dashboard", "/admin"];

export function proxy(req: NextRequest) {
  const { pathname } = req.nextUrl;

  const isProtected = PROTECTED_PREFIXES.some((prefix) =>
    pathname === prefix || pathname.startsWith(prefix + "/")
  );
  if (!isProtected) return NextResponse.next();

  // Check for any Supabase auth cookie (name pattern: sb-<ref>-auth-token).
  const hasCookie = [...req.cookies.getAll()].some((c) => c.name.includes("-auth-token"));

  if (!hasCookie) {
    const loginUrl = req.nextUrl.clone();
    loginUrl.pathname = "/login";
    loginUrl.searchParams.set("redirect", pathname);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*", "/admin/:path*"],
};

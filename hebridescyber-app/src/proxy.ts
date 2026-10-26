// Two jobs, in one pass over every page request:
//
// 1. Content-Security-Policy with a fresh per-request nonce (src/lib/csp.ts).
//    The nonce travels to the app in the request's `x-nonce` and CSP headers —
//    Next stamps it on its own scripts, layout.tsx stamps it on ours — and the
//    same policy goes back on the response. This is what lets script-src drop
//    'unsafe-inline'. Consequence: every page is rendered per request (a nonce
//    can't be baked into a statically generated page).
//
// 2. E-21: server-side auth protection via @supabase/ssr cookies. Refreshes
//    the session and redirects to /login if it is missing or expired, but ONLY
//    for the protected prefixes below.
//
// /login must never be protected: a signed-out visitor loading it would be
// redirected to /login, match again, and loop forever — nobody could sign in.
// Login brute-force protection doesn't belong here either: credentials go
// from the browser straight to Supabase Auth (src/lib/auth.ts), which
// rate-limits its own endpoints. tests/e2e/dashboard.spec.ts covers both halves.
import { NextRequest, NextResponse } from "next/server";
import { createMiddlewareClient } from "@/lib/supabase/middleware";
import { buildCsp, generateNonce } from "@/lib/csp";

const PROTECTED_PREFIXES = ["/dashboard", "/admin", "/account"];

export function isProtectedPath(pathname: string): boolean {
  return PROTECTED_PREFIXES.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

export async function proxy(original: NextRequest) {
  const nonce = generateNonce();
  const csp = buildCsp(nonce);
  const requestHeaders = new Headers(original.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);
  const req = new NextRequest(original, { headers: requestHeaders });

  let response: NextResponse;
  if (isProtectedPath(req.nextUrl.pathname)) {
    const { supabase, response: base } = createMiddlewareClient(req);
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) {
      const loginUrl = req.nextUrl.clone();
      loginUrl.pathname = "/login";
      loginUrl.searchParams.set("redirect", req.nextUrl.pathname);
      response = NextResponse.redirect(loginUrl);
    } else {
      response = base;
    }
  } else {
    response = NextResponse.next({ request: req });
  }

  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  // Pages only: API routes, build assets and static files get no nonce (they
  // are not HTML) and keep the static header set from next.config.mjs.
  matcher: [
    {
      source: "/((?!api/|_next/static|_next/image|favicon.svg|.*\.(?:png|jpg|svg|ico|webmanifest|txt|xml|html)$).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};

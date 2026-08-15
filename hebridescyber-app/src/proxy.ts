// Next.js 16 proxy = middleware.
// Auth protection is handled client-side in each page component (dashboard,
// admin) — the Supabase JS client stores sessions in localStorage, not
// httpOnly cookies, so server-side cookie checks cannot reliably determine
// auth state. Unauthenticated users who reach a protected page are shown
// "Sign in required" by the page component itself.

import { type NextRequest, NextResponse } from "next/server";

export function proxy(req: NextRequest) {
  void req;
  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*", "/admin/:path*"],
};

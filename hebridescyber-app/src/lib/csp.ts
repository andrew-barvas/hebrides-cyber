// Content-Security-Policy with a per-request nonce. Set from src/middleware.ts
// (the only place a fresh nonce can be minted per request); Next reads the
// nonce back out of the request's CSP header and stamps it on its own inline
// bootstrap scripts, so no 'unsafe-inline' is needed in script-src.
//
// script-src is 'nonce-…' + 'strict-dynamic': a nonced script may load further
// scripts (GA's gtag.js, chunks), and the 'self'/host allowlist entries are
// ignored by browsers that understand strict-dynamic — they remain only as a
// fallback for old browsers. style-src keeps 'unsafe-inline': Tailwind/Next
// emit inline style attributes, and inline *styles* are not a script-execution
// vector (headers.ts grades only script-src for this).

const SUPABASE = "https://*.supabase.co https://*.supabase.in";

export function generateNonce(): string {
  return btoa(crypto.randomUUID());
}

export function buildCsp(nonce: string, isDev = process.env.NODE_ENV === "development"): string {
  return [
    "default-src 'self'",
    // 'unsafe-eval' is dev-only: React uses eval for debug stack reconstruction.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' https://www.googletagmanager.com https://www.google-analytics.com${isDev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    `img-src 'self' data: blob: ${SUPABASE}`,
    `connect-src 'self' ${SUPABASE} wss://*.supabase.co wss://*.supabase.in https://www.google-analytics.com https://region1.google-analytics.com https://*.sentry.io`,
    "font-src 'self' data:",
    "frame-src https://js.stripe.com https://checkout.stripe.com",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self' https://checkout.stripe.com",
  ].join("; ");
}

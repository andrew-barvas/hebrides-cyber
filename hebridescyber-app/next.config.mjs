import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { withSentryConfig } from "@sentry/nextjs/config";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Same header set as staticwebapp.config.json's globalHeaders, duplicated
// here deliberately. Azure SWA's globalHeaders only decorate responses
// served directly from its static-file/CDN layer — confirmed by curling
// production and finding CSP/X-Frame-Options/etc entirely absent (even on
// a 404) while HSTS came through from Azure's own platform-level
// enforcement. Every route in this app (App Router pages, the pages/api
// Stripe webhook) runs through the managed Next.js server (Oryx Functions)
// in SWA's "hybrid" mode, which bypasses that header layer. Next's own
// headers() runs inside the server response path itself, so it's the one
// mechanism that reliably applies here. Keep both files in sync if the
// policy changes — staticwebapp.config.json still matters for any file
// served as a pure static asset without hitting the Next server.
const SECURITY_HEADERS = [
  { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  {
    key: "Content-Security-Policy",
    // connect-src includes https://*.sentry.io for E-03 (docs/ENHANCEMENTS.md)
    // -- the browser-side Sentry SDK (instrumentation-client.ts) posts
    // directly to Sentry's ingest endpoint from the client; without this the
    // existing strict CSP would silently block every client-side error
    // report with no visible error beyond a CSP console warning. Harmless
    // to keep even before SENTRY_DSN is actually configured.
    value:
      "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://www.google-analytics.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https://*.supabase.co https://*.supabase.in; connect-src 'self' https://*.supabase.co https://*.supabase.in wss://*.supabase.co wss://*.supabase.in https://www.google-analytics.com https://region1.google-analytics.com https://*.sentry.io; font-src 'self' data:; frame-src https://js.stripe.com https://checkout.stripe.com; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self' https://checkout.stripe.com",
  },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
  // require-corp is the strict setting our own headers.ts check wants —
  // every cross-origin subresource must opt in via its own
  // Cross-Origin-Resource-Policy header (or be loaded with `crossorigin`
  // under real CORS) or the browser blocks it outright. Re-check after
  // deploy: Google Analytics/Tag Manager's scripts and Stripe's checkout/js
  // iframes (both already CSP-allowlisted above) are the two genuinely
  // cross-origin things this app loads today and are the ones actually at
  // risk of silently breaking under this — both are commonly reported as
  // COEP-safe by their own vendors, but "commonly" isn't "verified against
  // this app," so confirm with a real browser load, not just curl -I.
  { key: "Cross-Origin-Embedder-Policy", value: "require-corp" },
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Drops the X-Powered-By: Next.js response header — free information
  // disclosure otherwise (flagged by our own scanner's headers.ts check).
  poweredByHeader: false,
  // Pins Turbopack's project root to this folder explicitly. Without this,
  // Turbopack (the Next.js 16 default bundler) walks up looking for a
  // workspace root and can land on a parent directory that happens to
  // contain another lockfile (e.g. a bun.lock in a home directory) —
  // harmless but noisy, and worth pinning down rather than relying on
  // inference once there's more than one JS project on the machine.
  turbopack: {
    root: __dirname,
  },
  async headers() {
    return [{ source: "/:path*", headers: SECURITY_HEADERS }];
  },
  // Deployed as Azure Static Web Apps "hybrid" mode (managed Functions) by
  // default — not a pure static export — see CLAUDE.md's Deployment
  // section. `output: 'standalone'` only turns on for the container build
  // (Dockerfile sets NEXT_OUTPUT_MODE=standalone before `npm run build`);
  // Oryx's SWA build never sets that var, so its build output is
  // unaffected. Standalone mode traces only the server code actually
  // reachable from a route, which is also why it's off by default — Oryx's
  // Next.js detection for SWA hybrid mode expects the regular `.next`
  // build output, not a standalone server bundle.
  output: process.env.NEXT_OUTPUT_MODE === "standalone" ? "standalone" : undefined,
};

// E-03 (docs/ENHANCEMENTS.md): wraps the build with Sentry's webpack plugin
// for source-map upload — needs SENTRY_ORG/SENTRY_PROJECT/SENTRY_AUTH_TOKEN
// to actually upload anything; all three are optional and the plugin skips
// the upload step (silently, since `silent: true` below) rather than
// failing the build when they're unset. Safe to leave wrapped unconditionally.
export default withSentryConfig(nextConfig, {
  org: process.env.SENTRY_ORG,
  project: process.env.SENTRY_PROJECT,
  authToken: process.env.SENTRY_AUTH_TOKEN,
  silent: true,
  // No tunnel route — this app's CSP already allowlists Sentry's ingest
  // domain directly (see connect-src above) rather than proxying error
  // reports through a first-party route to dodge ad-blockers, which isn't
  // a problem this product has.
  widenClientFileUpload: true,
  // disableLogger/automaticVercelMonitors deliberately omitted, not just
  // set to their old defaults — both are deprecated in favour of nested
  // webpack.* options that only apply under webpack, and this project
  // builds with Turbopack (next.config.mjs's own comment above), where
  // neither the old nor new option does anything.
});

import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

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
    value:
      "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://www.google-analytics.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https://*.supabase.co https://*.supabase.in; connect-src 'self' https://*.supabase.co https://*.supabase.in wss://*.supabase.co wss://*.supabase.in https://www.google-analytics.com https://region1.google-analytics.com; font-src 'self' data:; frame-src https://js.stripe.com https://checkout.stripe.com; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self' https://checkout.stripe.com",
  },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
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
  // Deployed as Azure Static Web Apps "hybrid" mode (managed Functions),
  // not a pure static export — see CLAUDE.md's Deployment section.
};

export default nextConfig;

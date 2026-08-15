import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Pins Turbopack's project root to this folder explicitly. Without this,
  // Turbopack (the Next.js 16 default bundler) walks up looking for a
  // workspace root and can land on a parent directory that happens to
  // contain another lockfile (e.g. a bun.lock in a home directory) —
  // harmless but noisy, and worth pinning down rather than relying on
  // inference once there's more than one JS project on the machine.
  turbopack: {
    root: __dirname,
  },
  // Static export works well with Azure Static Web Apps for the marketing
  // pages + client-rendered dashboard. If you need server-rendered routes
  // or the pages/api Stripe webhook to run on the same host, deploy the
  // Next.js app as a hosted Node app / Azure Static Web Apps "hybrid"
  // (managed Functions) instead of a pure static export.
  // TODO: decide export strategy before production deploy (see README).
};

export default nextConfig;

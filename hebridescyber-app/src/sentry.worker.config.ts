// Sentry error-tracking for the ephemeral scan worker
// (src/scripts/run-queued-scan-jobs.ts). Uses @sentry/node directly rather
// than @sentry/nextjs since the worker runs outside the Next.js runtime.
// Loaded as a side-effect import at the top of the worker script.
//
// Silent no-op when SENTRY_DSN is unset — matches all other optional
// external services in this codebase (Upstash, Resend, HIBP, Safe Browsing):
// ships safely with zero required action, starts working the moment a DSN
// is configured. See .env.example.
import * as Sentry from "@sentry/node";
import { scrubSentryEvent } from "./lib/sentryScrub";

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV,
  // Low sample rate — error capture is the goal here, not per-scan perf
  // tracing (same reasoning as sentry.server.config.ts).
  tracesSampleRate: 0.1,
  beforeSend: scrubSentryEvent,
});

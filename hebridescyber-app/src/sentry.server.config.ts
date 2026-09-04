// E-03 (docs/ENHANCEMENTS.md): server-side (Node runtime) error tracking.
// Loaded via instrumentation.ts's register(), never imported directly.
//
// dsn left unset (undefined) when SENTRY_DSN/NEXT_PUBLIC_SENTRY_DSN aren't
// configured — Sentry.init() with no dsn initializes into a real no-op
// state (captures nothing, throws nothing), matching every other optional
// external service in this codebase (Upstash rate limiting, Resend/
// SendGrid email, HIBP/Safe Browsing scanners): ships safely with zero
// required action, and starts working the moment a DSN is set. See
// .env.example for what's needed to actually turn this on.
import * as Sentry from "@sentry/nextjs";
import { scrubSentryEvent } from "@/lib/sentryScrub";

Sentry.init({
  dsn: process.env.SENTRY_DSN ?? process.env.NEXT_PUBLIC_SENTRY_DSN,
  environment: process.env.NODE_ENV,
  // Low sample rate — this app doesn't need per-request performance tracing
  // today (no perf problem this is meant to solve, see E-03's own scope:
  // "if a customer's scan fails, there's no way to find out why" — an error-
  // tracking gap, not a latency-tracking one). Kept non-zero rather than 0
  // so trace context still attaches to captured errors.
  tracesSampleRate: 0.1,
  beforeSend: scrubSentryEvent,
});

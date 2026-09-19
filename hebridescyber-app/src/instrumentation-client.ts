// E-03 (docs/ENHANCEMENTS.md): browser-side error tracking. Must read
// NEXT_PUBLIC_SENTRY_DSN specifically (not the server-only SENTRY_DSN) --
// this file ships in the client bundle, so only a NEXT_PUBLIC_-prefixed var
// is actually available to it at build time, same convention as every
// other client-visible env var in this app (NEXT_PUBLIC_SUPABASE_URL etc.).
//
// No session-replay/feedback integrations enabled -- this app's dashboard
// renders scan findings and account data; replay recording that surface by
// default is a bigger privacy decision than "turn on error tracking,"
// deliberately not made here.
import * as Sentry from "@sentry/nextjs";
import { scrubSentryEvent } from "@/lib/sentryScrub";

// Only initialise when a real DSN is configured (still pending E-03 as of
// 2026-09 — see docs/SPRINT-PLAN.md). Sentry.init() wires up its browser
// performance/tracing instrumentation (PerformanceObserver-based web-vitals
// collection) unconditionally as part of registering its integrations, even
// with an empty dsn — that instrumentation has been observed throwing
// "Cannot read properties of undefined (reading 'startTime')" from Sentry's
// own bundled code on some page loads. With no DSN there's nowhere for
// events to go anyway, so there's no reason to carry that risk for zero
// benefit; this re-enables itself automatically once NEXT_PUBLIC_SENTRY_DSN
// is set.
if (process.env.NEXT_PUBLIC_SENTRY_DSN) {
  Sentry.init({
    dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
    environment: process.env.NODE_ENV,
    tracesSampleRate: 0.1,
    beforeSend: scrubSentryEvent,
  });
}

export const onRouterTransitionStart = Sentry.captureRouterTransitionStart;

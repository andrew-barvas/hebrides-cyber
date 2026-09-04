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

Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  environment: process.env.NODE_ENV,
  tracesSampleRate: 0.1,
  beforeSend: scrubSentryEvent,
});

export const onRouterTransitionStart = Sentry.captureRouterTransitionStart;

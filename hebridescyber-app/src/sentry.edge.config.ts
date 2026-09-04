// E-03 (docs/ENHANCEMENTS.md): Edge runtime (proxy/middleware) error
// tracking. Loaded via instrumentation.ts's register(); same config as
// sentry.server.config.ts, kept as a separate file only because the Edge
// runtime is a distinct Next.js entry point Sentry requires its own init
// call for -- not a second, drifting copy of the setup decisions.
import * as Sentry from "@sentry/nextjs";
import { scrubSentryEvent } from "@/lib/sentryScrub";

Sentry.init({
  dsn: process.env.SENTRY_DSN ?? process.env.NEXT_PUBLIC_SENTRY_DSN,
  environment: process.env.NODE_ENV,
  tracesSampleRate: 0.1,
  beforeSend: scrubSentryEvent,
});

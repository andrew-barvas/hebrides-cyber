// E-03 (docs/ENHANCEMENTS.md): Next.js instrumentation entry point --
// register() runs once per runtime at startup and is where server/edge
// Sentry init actually gets loaded (not imported at the top of this file
// directly, since sentry.server.config.ts uses Node APIs the Edge runtime
// doesn't have, and vice versa isn't a risk but keeping them fully
// separate per Sentry's own recommended pattern avoids any doubt).
//
// onRequestError below is what actually captures an error thrown inside an
// API route handler or server component -- the piece that answers E-03's
// stated problem directly ("if a customer's scan fails in production
// today, there is no way to find out why").
import * as Sentry from "@sentry/nextjs";

export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    await import("./sentry.server.config");
  }
  if (process.env.NEXT_RUNTIME === "edge") {
    await import("./sentry.edge.config");
  }
}

export const onRequestError = Sentry.captureRequestError;

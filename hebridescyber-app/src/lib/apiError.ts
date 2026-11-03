// Shared 500 response for an unexpected database/service error in an API
// route.
//
// Routes used to answer `res.status(500).json({ error: error.message })`,
// which sent Postgres's own text to the browser — table, column and
// constraint names ('violates check constraint "scans_status_check"'), RLS
// policy names, sometimes a SQL hint. That is the "verbose error message"
// finding our own scanner reports on customer sites (CWE-209). It also never
// reached Sentry: onRequestError (instrumentation.ts) only fires on a *thrown*
// error, and these were handled returns, so the detail survived only in the
// customer's browser.
//
// This keeps the detail server-side — logged with the route and, when a DSN
// is set, captured in Sentry — and answers with a fixed, non-revealing
// message. Admin routes (src/pages/api/admin/**) keep returning the raw text
// on purpose: they are behind requireAdmin and that text is the owner's
// fastest diagnostic.
import type { NextApiResponse } from "next";
import * as Sentry from "@sentry/nextjs";

export const INTERNAL_ERROR_MESSAGE = "Something went wrong on our side. Please try again.";

type ErrorLike = { message?: string; code?: string } | null | undefined;

/**
 * Logs `err` (with `route` for context) and answers `status` (default 500)
 * with a generic message. `publicMessage` overrides the generic text with
 * route-specific wording that must not include anything from `err`; `extra`
 * adds stable machine-readable fields such as `code`.
 */
export function respondInternalError(
  res: NextApiResponse,
  route: string,
  err: ErrorLike,
  opts: { status?: number; publicMessage?: string; extra?: Record<string, unknown> } = {}
): void {
  const detail = err?.message ?? "unknown error";
  console.error(`[${route}] ${detail}${err?.code ? ` (code ${err.code})` : ""}`);
  Sentry.captureMessage(`${route}: ${detail}`, { level: "error", tags: { route, db_code: err?.code } });
  res.status(opts.status ?? 500).json({ error: opts.publicMessage ?? INTERNAL_ERROR_MESSAGE, ...opts.extra });
}

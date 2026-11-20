// What the customer's engagement status page says about an engagement, in plain
// words. Pure, so the wording and the "is testing allowed right now?" answer are
// unit-tested. The answer mirrors the worker gate's time and state rules
// (checkScope "active"); the gate itself stays the authority; this only reports.
import { isBeforeExpiry, isWindowOpen } from "./exploitability/scope/engagementState";
import type { EngagementState } from "./exploitability/types";

export const STATE_LABEL: Readonly<Record<EngagementState, { title: string; detail: string }>> = {
  booked: { title: "Booked", detail: "We're agreeing the scope with you. Nothing is tested yet." },
  scoped: { title: "Scope agreed", detail: "Waiting for the signed documents and your authorisation of each system in scope. Nothing is tested yet." },
  authorised: { title: "Authorised", detail: "Everything is signed. Testing can start once the testing window opens." },
  in_window: { title: "Testing window open", detail: "Testing may run during the agreed times below." },
  reported: { title: "Testing finished", detail: "Testing has ended. Your report is being written or is ready." },
  closed: { title: "Closed", detail: "This engagement is finished." },
  aborted: { title: "Stopped", detail: "Testing was stopped and every authorisation for this engagement was withdrawn." },
};

/** The stop button shows for every state but closed and already stopped. */
export function canStop(state: EngagementState): boolean {
  return state !== "closed" && state !== "aborted";
}

/** Can the customer sign an authorisation against this engagement now? Only before it is authorised. */
export function canAuthorise(state: EngagementState): boolean {
  return state === "booked" || state === "scoped";
}

export type TestingNow = { allowed: true } | { allowed: false; why: string };

/** Could testing run at this moment, by the engagement's state, window, testing windows and expiry? */
export function testingAllowedNow(
  engagement: { state: EngagementState; window_start: string | null; window_end: string | null; expires_at: string | null },
  testingWindows: readonly { starts_at: string; ends_at: string }[],
  now: Date,
): TestingNow {
  if (engagement.state !== "authorised" && engagement.state !== "in_window") return { allowed: false, why: STATE_LABEL[engagement.state].title };
  if (!isWindowOpen(engagement.window_start, engagement.window_end, now)) return { allowed: false, why: "Outside the agreed window" };
  if (!isBeforeExpiry(engagement.expires_at, now)) return { allowed: false, why: "The engagement has expired" };
  if (testingWindows.length > 0 && !testingWindows.some((w) => isWindowOpen(w.starts_at, w.ends_at, now))) return { allowed: false, why: "Outside today's testing times" };
  return { allowed: true };
}

/** "1 Dec 2026, 09:00" in the viewer's own time zone, or "Not set". */
export function formatWhen(iso: string | null | undefined, locale?: string, timeZone?: string): string {
  if (!iso) return "Not set";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "Not set";
  return new Intl.DateTimeFormat(locale ?? "en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone }).format(new Date(t));
}

export const CONTACT_LABEL: Readonly<Record<string, string>> = {
  authoriser: "Authorised by",
  technical: "Technical contact",
  emergency: "Emergency stop contact",
};

/** Mirrors MAX_AUTHORIZATION_DAYS (offensiveAuthorization.ts, migration 082); a test holds them equal. Not imported, to keep server code out of the page bundle. */
export const AUTHORISATION_MAX_DAYS = 30;

/**
 * The expiry the status page asks for when the customer authorises a host: the
 * engagement's own expiry, or as far as the 30-day limit allows if that is
 * sooner (a minute short of it, so the request is never over the limit on arrival).
 */
export function authorisationExpiryFor(engagementExpiresAt: string | null, now: Date): string {
  const cap = now.getTime() + AUTHORISATION_MAX_DAYS * 24 * 60 * 60 * 1000 - 60_000;
  const engagementEnd = engagementExpiresAt ? Date.parse(engagementExpiresAt) : NaN;
  return new Date(!Number.isNaN(engagementEnd) && engagementEnd > now.getTime() && engagementEnd < cap ? engagementEnd : cap).toISOString();
}

/** Would an authorisation signed now end before the testing window does? Then moving to authorised will refuse it. */
export function authorisationEndsBeforeWindow(engagement: { window_end: string | null; expires_at: string | null }, now: Date): boolean {
  const windowEnd = engagement.window_end ? Date.parse(engagement.window_end) : NaN;
  if (Number.isNaN(windowEnd)) return false;
  return Date.parse(authorisationExpiryFor(engagement.expires_at, now)) < windowEnd;
}

// What the admin Engagements tab says and sends (Exploit, P-07). Pure, so the
// wording of every refusal and the date conversion are unit-tested. The routes
// under /api/engagements* decide; this only explains their answers to the analyst.
import type { ScopeHostRefusal, WindowProblem } from "./engagements";
import type { TransitionRefusal } from "./exploitability/scope/engagementState";
import type { EngagementState } from "./exploitability/types";

/** The one forward move from each state, as the state machine allows it. Stopping is separate. */
export const NEXT_STATE: Readonly<Partial<Record<EngagementState, EngagementState>>> = {
  booked: "scoped",
  scoped: "authorised",
  authorised: "in_window",
  in_window: "reported",
  reported: "closed",
};

/** Why a state change was refused, as the analyst should read it: what to do next. */
export const REFUSAL_TEXT: Readonly<Record<TransitionRefusal, string>> = {
  transition_not_allowed: "That isn't the next step from the engagement's current state.",
  contract_not_signed: "Record the signed contract first.",
  roe_not_signed: "Record the signed rules of engagement first.",
  window_not_set: "Set the engagement window, with an end after its start, first.",
  expiry_not_set: "Set an expiry on or after the end of the engagement window first.",
  no_emergency_contact: "Add at least one emergency stop contact first.",
  no_included_hosts: "Add at least one in-scope host first.",
  domain_not_verified: "The customer hasn't verified ownership of this host's domain.",
  authorization_missing: "The customer hasn't signed a current authorisation for this host, linked to this engagement.",
  authorization_ends_before_window: "The customer's authorisation for this host ends before the engagement window does. Ask them to sign a new one that lasts until the window closes, or shorten the window.",
  outside_window: "The engagement window isn't open now.",
  engagement_expired: "The engagement has expired.",
};

/** A refusal from PATCH /api/engagements/{id}, in words. Unknown reasons fall back to the route's own message. */
export function describeRefusal(body: { error?: unknown; reason?: unknown; host?: unknown }, fallback: string): string {
  const reason = typeof body.reason === "string" && Object.hasOwn(REFUSAL_TEXT, body.reason) ? REFUSAL_TEXT[body.reason as TransitionRefusal] : null;
  if (!reason) return typeof body.error === "string" ? body.error : fallback;
  return typeof body.host === "string" ? `${body.host}: ${reason}` : reason;
}

export const SCOPE_REFUSAL_TEXT: Readonly<Record<ScopeHostRefusal["reason"], string>> = {
  invalid_host: "not a valid host name",
  domain_not_verified: "the customer hasn't verified this domain, so it can't be in scope (it can still be excluded)",
  not_listed: "not on the scope list",
};

export const WINDOW_PROBLEM_TEXT: Readonly<Record<WindowProblem, string>> = {
  window_not_set: "Set the engagement's overall window first.",
  end_before_start: "Each testing window must end after it starts.",
  outside_engagement_window: "Each testing window must sit inside the engagement's overall window.",
};

/** Host names from a box the analyst typed or pasted into: one per line, or separated by commas or spaces. */
export function parseHosts(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).map((h) => h.trim().toLowerCase()).filter(Boolean))];
}

export const SHA256 = /^[0-9a-f]{64}$/;

/** An ISO timestamp as a `datetime-local` input value, in the browser's own time zone. Empty when unset or unreadable. */
export function toLocalInput(iso: string | null | undefined): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const d = new Date(t);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** A `datetime-local` value (browser time zone) as the ISO timestamp the API takes, or null when empty or unreadable. */
export function fromLocalInput(value: string): string | null {
  if (!value.trim()) return null;
  const t = new Date(value).getTime();
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

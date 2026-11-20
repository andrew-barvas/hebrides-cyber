import { describe, it, expect } from "vitest";
import { ENGAGEMENT_STATES } from "./exploitability/scope/engagementState";
import { AUTHORISATION_MAX_DAYS, STATE_LABEL, authorisationEndsBeforeWindow, authorisationExpiryFor, canAuthorise, canStop, formatWhen, testingAllowedNow } from "./engagementStatus";

const NOW = new Date("2026-11-06T12:00:00Z");
const open = { state: "in_window" as const, window_start: "2026-11-06T00:00:00Z", window_end: "2026-11-07T00:00:00Z", expires_at: "2026-11-08T00:00:00Z" };

describe("STATE_LABEL", () => {
  it("has plain words for every state, naming no tool or technique", () => {
    for (const state of ENGAGEMENT_STATES) {
      expect(STATE_LABEL[state].title.length).toBeGreaterThan(0);
      expect(STATE_LABEL[state].detail).not.toMatch(/sqlmap|hydra|ffuf|nuclei|strix|cairn|exploit|payload|brute/i);
    }
  });
});

describe("canStop and canAuthorise", () => {
  it("offers the stop in every state but closed and stopped", () => {
    for (const state of ENGAGEMENT_STATES) expect(canStop(state), state).toBe(state !== "closed" && state !== "aborted");
  });
  it("offers authorising only before the engagement is authorised", () => {
    for (const state of ENGAGEMENT_STATES) expect(canAuthorise(state), state).toBe(state === "booked" || state === "scoped");
  });
});

describe("testingAllowedNow", () => {
  it("is allowed inside the window, before expiry, in an allowed state", () => {
    expect(testingAllowedNow(open, [], NOW)).toEqual({ allowed: true });
    expect(testingAllowedNow({ ...open, state: "authorised" }, [], NOW)).toEqual({ allowed: true });
  });

  it("says why not, matching the gate's rules", () => {
    expect(testingAllowedNow({ ...open, state: "aborted" }, [], NOW)).toEqual({ allowed: false, why: "Stopped" });
    expect(testingAllowedNow({ ...open, state: "scoped" }, [], NOW)).toEqual({ allowed: false, why: "Scope agreed" });
    expect(testingAllowedNow({ ...open, window_end: "2026-11-06T06:00:00Z", expires_at: "2026-11-06T06:00:00Z" }, [], NOW)).toEqual({ allowed: false, why: "Outside the agreed window" });
    expect(testingAllowedNow({ ...open, expires_at: null }, [], NOW)).toEqual({ allowed: false, why: "The engagement has expired" });
    expect(testingAllowedNow(open, [{ starts_at: "2026-11-06T13:00:00Z", ends_at: "2026-11-06T17:00:00Z" }], NOW)).toEqual({ allowed: false, why: "Outside today's testing times" });
    expect(testingAllowedNow(open, [{ starts_at: "2026-11-06T09:00:00Z", ends_at: "2026-11-06T17:00:00Z" }], NOW)).toEqual({ allowed: true });
  });
});

describe("formatWhen", () => {
  it("formats a time and says Not set for nothing or nonsense", () => {
    expect(formatWhen("2026-12-01T09:00:00Z", "en-GB", "UTC")).toBe("1 Dec 2026, 09:00");
    expect(formatWhen(null)).toBe("Not set");
    expect(formatWhen("whenever")).toBe("Not set");
  });
});

describe("authorisationExpiryFor and authorisationEndsBeforeWindow", () => {
  const DAY = 86_400_000;
  it("asks for the engagement's expiry when it is inside the 30-day limit", () => {
    expect(authorisationExpiryFor("2026-11-20T00:00:00.000Z", NOW)).toBe("2026-11-20T00:00:00.000Z");
  });
  it("stops just short of the limit when the engagement runs longer, or has no usable expiry", () => {
    const cap = new Date(NOW.getTime() + 30 * DAY - 60_000).toISOString();
    expect(authorisationExpiryFor("2027-06-01T00:00:00.000Z", NOW)).toBe(cap);
    expect(authorisationExpiryFor(null, NOW)).toBe(cap);
    expect(authorisationExpiryFor("2026-11-01T00:00:00.000Z", NOW)).toBe(cap);
  });
  it("warns only when the authorisation would end before the window does", () => {
    expect(authorisationEndsBeforeWindow({ window_end: "2026-11-10T00:00:00Z", expires_at: "2026-11-12T00:00:00Z" }, NOW)).toBe(false);
    expect(authorisationEndsBeforeWindow({ window_end: "2027-01-31T00:00:00Z", expires_at: "2027-02-01T00:00:00Z" }, NOW)).toBe(true);
    expect(authorisationEndsBeforeWindow({ window_end: null, expires_at: null }, NOW)).toBe(false);
  });
  it("matches the server's limit", async () => {
    const { MAX_AUTHORIZATION_DAYS } = await import("./offensiveAuthorization");
    expect(AUTHORISATION_MAX_DAYS).toBe(MAX_AUTHORIZATION_DAYS);
  });
});

describe("formatWhen defaults", () => {
  it("formats in en-GB when no locale is given", () => {
    expect(formatWhen("2026-12-01T09:00:00Z", undefined, "UTC")).toBe("1 Dec 2026, 09:00");
  });
});

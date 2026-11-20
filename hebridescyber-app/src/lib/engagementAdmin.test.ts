import { describe, it, expect } from "vitest";
import { ENGAGEMENT_STATES, canTransition } from "./exploitability/scope/engagementState";
import { NEXT_STATE, REFUSAL_TEXT, SCOPE_REFUSAL_TEXT, WINDOW_PROBLEM_TEXT, describeRefusal, fromLocalInput, parseHosts, toLocalInput } from "./engagementAdmin";

const TOOLS = /sqlmap|hydra|ffuf|nuclei|strix|cairn|exploit|payload|brute|spray/i;

describe("NEXT_STATE", () => {
  it("offers exactly the forward moves the state machine allows", () => {
    for (const from of ENGAGEMENT_STATES) {
      for (const to of ENGAGEMENT_STATES) {
        if (to === "aborted") continue;
        expect(NEXT_STATE[from] === to, `${from} -> ${to}`).toBe(canTransition(from, to));
      }
    }
  });
});

describe("refusal wording", () => {
  it("is plain and names no tool or technique", () => {
    for (const text of [...Object.values(REFUSAL_TEXT), ...Object.values(SCOPE_REFUSAL_TEXT), ...Object.values(WINDOW_PROBLEM_TEXT)]) {
      expect(text.length).toBeGreaterThan(0);
      expect(text).not.toMatch(TOOLS);
    }
  });

  it("explains a known reason, naming the host when there is one", () => {
    expect(describeRefusal({ error: "The engagement can't move to that state.", reason: "no_emergency_contact" }, "x")).toBe("Add at least one emergency stop contact first.");
    expect(describeRefusal({ reason: "domain_not_verified", host: "shop.example.com" }, "x")).toBe("shop.example.com: The customer hasn't verified ownership of this host's domain.");
    expect(describeRefusal({ reason: "authorization_ends_before_window", host: "shop.example.com" }, "x")).toMatch(/^shop\.example\.com: The customer's authorisation for this host ends before the engagement window does\./);
  });

  it("falls back to the route's message, then to the caller's, for anything else", () => {
    expect(describeRefusal({ error: "The engagement changed while this request was running." }, "x")).toBe("The engagement changed while this request was running.");
    expect(describeRefusal({ error: "Odd", reason: "toString" }, "x")).toBe("Odd");
    expect(describeRefusal({}, "Could not move the engagement.")).toBe("Could not move the engagement.");
  });
});

describe("parseHosts", () => {
  it("splits on lines, commas and spaces, lower-cases and drops repeats", () => {
    expect(parseHosts("Shop.example.com\nwww.example.com, legacy.example.com  shop.example.com\n\n")).toEqual(["shop.example.com", "www.example.com", "legacy.example.com"]);
    expect(parseHosts("  ")).toEqual([]);
  });
});

describe("datetime-local conversion", () => {
  it("round-trips a timestamp to the minute", () => {
    const iso = "2026-12-01T09:30:00.000Z";
    expect(fromLocalInput(toLocalInput(iso))).toBe(iso);
  });

  it("treats empty or unreadable values as unset", () => {
    expect(toLocalInput(null)).toBe("");
    expect(toLocalInput("not a date")).toBe("");
    expect(fromLocalInput("")).toBeNull();
    expect(fromLocalInput("not a date")).toBeNull();
  });
});

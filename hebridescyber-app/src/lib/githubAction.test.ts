// The packaged GitHub Action (action/index.js at the repo root) is a plain,
// dependency-free CommonJS script outside this app, so it has no test runner
// of its own. Loaded here through Node's require — it only starts a scan when
// run as the entry point.
import { describe, it, expect } from "vitest";
import { createRequire } from "node:module";
import path from "node:path";

const require = createRequire(import.meta.url);
const action = require(path.resolve(process.cwd(), "..", "action", "index.js")) as {
  isTriaged: (finding: unknown, now?: number) => boolean;
  blockingFindings: (findings: unknown[], failOn: string, now?: number) => Array<{ check_id: string }>;
};

const NOW = Date.parse("2026-10-01T12:00:00Z");
const finding = (check_id: string, severity: string, extra: Record<string, unknown> = {}) => ({
  check_id, severity, title: check_id, status: "new", ...extra,
});
const triage = (state: string, expires_at: string | null = null) => ({ state, reason: "documented", expires_at, triaged_at: "2026-09-01T00:00:00Z" });

describe("action isTriaged", () => {
  it("is true for a triage with no expiry or a future one", () => {
    expect(action.isTriaged(finding("a", "high", { triage: triage("accepted_risk") }), NOW)).toBe(true);
    expect(action.isTriaged(finding("a", "high", { triage: triage("snoozed", "2026-10-05T00:00:00Z") }), NOW)).toBe(true);
  });

  it("is false with no triage, a null triage, or an expired one", () => {
    expect(action.isTriaged(finding("a", "high"), NOW)).toBe(false);
    expect(action.isTriaged(finding("a", "high", { triage: null }), NOW)).toBe(false);
    expect(action.isTriaged(finding("a", "high", { triage: triage("snoozed", "2026-09-30T00:00:00Z") }), NOW)).toBe(false);
    expect(action.isTriaged(finding("a", "high", { triage: triage("snoozed", "not a date") }), NOW)).toBe(false);
  });
});

describe("action blockingFindings", () => {
  const findings = [
    finding("new-high", "high"),
    finding("new-high-fp", "high", { triage: triage("false_positive") }),
    finding("new-crit-snoozed", "critical", { triage: triage("snoozed", "2026-10-31T00:00:00Z") }),
    finding("new-crit-expired", "critical", { triage: triage("snoozed", "2026-09-01T00:00:00Z") }),
    finding("old-crit", "critical", { status: "unchanged" }),
    finding("new-low", "low"),
  ];

  it("ignores actively triaged findings when deciding pass/fail", () => {
    expect(action.blockingFindings(findings, "high", NOW).map((f) => f.check_id)).toEqual(["new-high", "new-crit-expired"]);
  });

  it("passes when every blocking finding is triaged", () => {
    expect(action.blockingFindings([findings[1], findings[2]], "low", NOW)).toEqual([]);
  });

  it("never blocks with fail-on none", () => {
    expect(action.blockingFindings(findings, "none", NOW)).toEqual([]);
  });
});

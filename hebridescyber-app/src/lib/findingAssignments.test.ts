import { describe, expect, it } from "vitest";
import { assignmentKey, buildAssignmentIndex } from "./findingAssignments";
import { applyFilters, DEFAULT_FILTERS, parseFindingsQuery, type FindingRow } from "./findingsView";

const owner = { id: "owner", email: "owner@example.com", role: "owner" };
const dev = { id: "dev", email: "dev@example.com", role: "developer" };

describe("buildAssignmentIndex", () => {
  it("indexes by host and checkId, and drops anyone no longer on the account", () => {
    const index = buildAssignmentIndex(
      [
        { target_host: "WWW.example.com", check_id: "headers.hsts", assignee: "dev", assigned_at: "2026-11-19T00:00:00Z" },
        { target_host: "www.example.com", check_id: "dns.spf", assignee: "left-the-team", assigned_at: "2026-11-19T00:00:00Z" },
      ],
      [owner, dev]
    );
    expect(index.get(assignmentKey("www.example.com", "headers.hsts"))).toEqual(dev);
    expect(index.has(assignmentKey("www.example.com", "dns.spf"))).toBe(false);
  });
});

describe("assignee filter", () => {
  const row = (key: string, assignee: FindingRow["assignee"]) => ({ key, triage: null, assignee }) as unknown as FindingRow;
  const rows = [row("a", { id: "dev", email: "dev@example.com" }), row("b", null), row("c", undefined)];

  it("parses only 'unassigned' or a user id", () => {
    expect(parseFindingsQuery({ assignee: "unassigned" }).filters.assignee).toBe("unassigned");
    expect(parseFindingsQuery({ assignee: "22222222-2222-4222-8222-222222222222" }).filters.assignee).toBe("22222222-2222-4222-8222-222222222222");
    expect(parseFindingsQuery({ assignee: "robert'); drop" }).filters.assignee).toBeUndefined();
  });

  it("keeps unassigned rows, or only one person's", () => {
    expect(applyFilters(rows, { ...DEFAULT_FILTERS, assignee: "unassigned" }).map((r) => r.key)).toEqual(["b", "c"]);
    expect(applyFilters(rows, { ...DEFAULT_FILTERS, assignee: "dev" }).map((r) => r.key)).toEqual(["a"]);
    expect(applyFilters(rows, DEFAULT_FILTERS).map((r) => r.key)).toEqual(["a", "b", "c"]);
  });
});

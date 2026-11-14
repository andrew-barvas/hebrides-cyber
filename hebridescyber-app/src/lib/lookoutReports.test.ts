import { describe, it, expect } from "vitest";
import { canTransition, draftItemsFromRanking, draftSummary } from "./lookoutReports";
import type { PrioritisedFinding } from "./estatePriority";
import type { EstateDrift } from "./estateDrift";

const ranked = (n: number) =>
  Array.from({ length: n }, (_, i) => ({ host: `h${i}.example.com`, checkId: `c.${i}`, severity: "high", title: `Finding ${i}` }) as unknown as PrioritisedFinding);
const counts = (total: number) => ({ critical: 0, high: total, medium: 0, low: 0, total });

describe("draftItemsFromRanking", () => {
  it("takes the top ten in ranking order, all included, with empty analyst fields", () => {
    const items = draftItemsFromRanking(ranked(14));
    expect(items).toHaveLength(10);
    expect(items[0]).toEqual({ host: "h0.example.com", check_id: "c.0", severity: "high", title: "Finding 0", priority: 1, analyst_note: "", business_impact: "", included: true });
    expect(items.map((i) => i.priority)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(draftItemsFromRanking([])).toEqual([]);
  });
});

describe("draftSummary", () => {
  it("states the period's changes plainly for the analyst to rewrite", () => {
    const drift = { opened: counts(1), fixed: counts(3), openNow: counts(5), newHosts: ["new.example.com"], hosts: [], notableOpened: [], since: "", until: "" } as EstateDrift;
    expect(draftSummary(drift)).toBe("In this period 1 new issue appeared and 3 were fixed; 5 remain open. We found 1 new hostname: new.example.com.");
    expect(draftSummary(null)).toBe("");
  });
});

describe("canTransition", () => {
  it("lets admins publish and unpublish, and only the customer acknowledge a published report", () => {
    expect(canTransition("draft", "published", "admin")).toBe(true);
    expect(canTransition("published", "draft", "admin")).toBe(true);
    expect(canTransition("acknowledged", "draft", "admin")).toBe(false);
    expect(canTransition("published", "acknowledged", "admin")).toBe(false);
    expect(canTransition("published", "acknowledged", "customer")).toBe(true);
    expect(canTransition("draft", "acknowledged", "customer")).toBe(false);
  });
});

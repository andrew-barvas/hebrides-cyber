import { describe, expect, it } from "vitest";
import { buildPublicPlan, hashPlanToken, isPlanToken, newPlanToken, planUnavailable, planUrl, type PlanItemRow, type PlanRow } from "./fixPlans";

const plan: PlanRow = { id: "p1", owner: "o1", target_host: "shop.example.com", title: "", created_at: "2026-11-01T00:00:00Z", expires_at: "2027-01-30T00:00:00Z", revoked_at: null };
const item = (check_id: string, position: number, extra: Partial<PlanItemRow> = {}): PlanItemRow => ({ check_id, position, severity: "high", title: check_id, remediation: "Do the thing", client_done_at: null, client_note: "", ...extra });

describe("tokens", () => {
  it("makes a 43-character link token and stores only its SHA-256", () => {
    const { token, hash } = newPlanToken();
    expect(isPlanToken(token)).toBe(true);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hashPlanToken(token)).toBe(hash);
    expect(hash).not.toContain(token);
  });

  it("rejects anything else before a lookup", () => {
    expect(isPlanToken("short")).toBe(false);
    expect(isPlanToken(`${"a".repeat(42)}!`)).toBe(false);
    expect(isPlanToken(undefined)).toBe(false);
  });

  it("builds a www link", () => {
    expect(planUrl("abc", "https://www.hebridescyber.co.uk/")).toBe("https://www.hebridescyber.co.uk/plan/abc");
  });
});

describe("planUnavailable", () => {
  const now = new Date("2026-12-01T00:00:00Z");
  it("gives one message for missing, revoked and expired links, so a link's history isn't revealed", () => {
    const missing = planUnavailable(null, now);
    expect(planUnavailable({ ...plan, revoked_at: "2026-11-10T00:00:00Z" }, now)).toBe(missing);
    expect(planUnavailable({ ...plan, expires_at: "2026-11-30T00:00:00Z" }, now)).toBe(missing);
    expect(planUnavailable(plan, now)).toBeNull();
  });
});

describe("buildPublicPlan", () => {
  it("orders items and takes fixed from the owner's scans first, then the link holder's word", () => {
    const resolved = new Map<string, string | null>([
      ["a", "2026-11-05T00:00:00Z"],
      ["b", null],
    ]);
    const view = buildPublicPlan(
      plan,
      [item("c", 3), item("a", 1, { client_done_at: "2026-11-04T00:00:00Z" }), item("b", 2, { client_done_at: "2026-11-06T00:00:00Z", client_note: "Updated the plugin" })],
      resolved
    );
    expect(view.items.map((i) => [i.checkId, i.status])).toEqual([
      ["a", "fixed"],
      ["b", "marked_done"],
      ["c", "open"],
    ]);
    expect(view.items[0].fixedAt).toBe("2026-11-05T00:00:00Z");
    expect(view.items[1].note).toBe("Updated the plugin");
    expect(view.progress).toEqual({ fixed: 1, markedDone: 1, open: 1, total: 3 });
  });

  it("names an untitled plan after its site, and exposes no owner id", () => {
    const view = buildPublicPlan(plan, [], new Map());
    expect(view.title).toBe("Fix plan for shop.example.com");
    expect(JSON.stringify(view)).not.toContain("o1");
  });
});

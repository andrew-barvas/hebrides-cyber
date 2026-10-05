import { describe, it, expect } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  applyTriage,
  buildTriageIndex,
  effectiveTriage,
  excludeFalsePositives,
  expiryProblem,
  isTriageActive,
  loadTriageForHost,
  loadTriageIndexForTarget,
  normaliseTriageHost,
  partitionByTriage,
  reasonLength,
  type TriageDbRow,
} from "./findingTriage";
import { scoreFromFindings, type Finding } from "./scanners";

const NOW = new Date("2026-10-01T12:00:00Z");
const inDays = (n: number) => new Date(NOW.getTime() + n * 86_400_000).toISOString();

function row(checkId: string, overrides: Partial<TriageDbRow> = {}): TriageDbRow {
  return {
    id: `id-${checkId}`, owner: "o1", target_host: "shop.example", check_id: checkId, state: "accepted_risk",
    reason: "Agreed with the client", expires_at: null, created_by: "o1",
    created_at: inDays(-10), updated_at: inDays(-2), ...overrides,
  };
}

const finding = (checkId: string | undefined, severity: Finding["severity"] = "high"): Finding => ({ severity, title: `T ${checkId}`, detail: "d", checkId });

describe("isTriageActive / effectiveTriage", () => {
  it("treats no expiry as permanent and a future expiry as active", () => {
    expect(isTriageActive({ expires_at: null }, NOW)).toBe(true);
    expect(isTriageActive({ expires_at: inDays(1) }, NOW)).toBe(true);
  });

  it("treats a past, exactly-now or unparseable expiry as no triage", () => {
    expect(isTriageActive({ expires_at: inDays(-1) }, NOW)).toBe(false);
    expect(isTriageActive({ expires_at: NOW.toISOString() }, NOW)).toBe(false);
    expect(isTriageActive({ expires_at: "soon" }, NOW)).toBe(false);
    expect(effectiveTriage(row("a", { state: "snoozed", expires_at: inDays(-1) }), NOW)).toBeNull();
    expect(effectiveTriage(null, NOW)).toBeNull();
    expect(effectiveTriage(row("a"), NOW)?.check_id).toBe("a");
  });
});

describe("normaliseTriageHost", () => {
  it("accepts a bare host or a URL, lowercased, without port or path", () => {
    expect(normaliseTriageHost("Shop.Example")).toBe("shop.example");
    expect(normaliseTriageHost("https://Shop.Example:8443/path?q=1")).toBe("shop.example");
    expect(normaliseTriageHost("  shop.example  ")).toBe("shop.example");
  });

  it("rejects what isn't a host", () => {
    expect(normaliseTriageHost("")).toBeNull();
    expect(normaliseTriageHost("not a host")).toBeNull();
  });
});

describe("buildTriageIndex", () => {
  it("indexes only active rows with a known state, by host and checkId", () => {
    const index = buildTriageIndex(
      [
        row("a"),
        row("b", { state: "snoozed", expires_at: inDays(-1) }),
        row("c", { state: "bogus" as never }),
        row("d", { target_host: "other.example" }),
      ],
      NOW
    );
    expect(index.size).toBe(2);
    expect(index.get("SHOP.example", "a")?.state).toBe("accepted_risk");
    expect(index.get("shop.example", "b")).toBeUndefined();
    expect(index.get("shop.example", "c")).toBeUndefined();
    expect(index.get("shop.example", "d")).toBeUndefined();
    expect(index.get("other.example", "d")).toBeDefined();
    expect(index.get("shop.example", undefined)).toBeUndefined();
  });

  it("works for any checkId, including keyed ones", () => {
    const id = "script-inventory.unreviewed:https://cdn.example.net";
    expect(buildTriageIndex([row(id)], NOW).get("shop.example", id)).toBeDefined();
  });
});

describe("applying triage to findings", () => {
  const index = buildTriageIndex(
    [
      row("fp", { state: "false_positive", reason: "WAF page" }),
      row("acc"),
      row("snz", { state: "snoozed", expires_at: inDays(7) }),
      row("expired", { state: "false_positive", expires_at: inDays(-1) }),
    ],
    NOW
  );
  const findings = [finding("fp", "critical"), finding("acc", "high"), finding("snz", "medium"), finding("expired", "high"), finding(undefined, "low")];

  it("attaches the active triage, or null", () => {
    const out = applyTriage(findings, "shop.example", index);
    expect(out.map((f) => f.triage?.state ?? null)).toEqual(["false_positive", "accepted_risk", "snoozed", null, null]);
    expect(out[0].triage).toEqual({ state: "false_positive", reason: "WAF page", expiresAt: null, triagedAt: inDays(-2) });
  });

  it("partitions open from triaged", () => {
    const { open, triaged } = partitionByTriage(findings, "shop.example", index);
    expect(open.map((f) => f.checkId)).toEqual(["expired", undefined]);
    expect(triaged.map((f) => f.checkId)).toEqual(["fp", "acc", "snz"]);
  });

  // Only false positives leave the score: an accepted or snoozed risk is still a risk.
  it("excludes only false positives from the score", () => {
    const scored = excludeFalsePositives(findings, "shop.example", index);
    expect(scored.map((f) => f.checkId)).toEqual(["acc", "snz", "expired", undefined]);
    expect(scoreFromFindings(findings)).toBe(100 - 30 - 15 - 7 - 15 - 2);
    expect(scoreFromFindings(scored)).toBe(100 - 15 - 7 - 15 - 2);
  });

  it("leaves the score alone with no triage", () => {
    expect(excludeFalsePositives(findings, "shop.example", buildTriageIndex([], NOW))).toHaveLength(findings.length);
  });
});

describe("expiryProblem", () => {
  it("requires an expiry for a snooze only", () => {
    expect(expiryProblem("snoozed", null, NOW)).toMatch(/needs an expiry/);
    expect(expiryProblem("snoozed", undefined, NOW)).toMatch(/needs an expiry/);
    expect(expiryProblem("accepted_risk", null, NOW)).toBeNull();
    expect(expiryProblem("false_positive", undefined, NOW)).toBeNull();
  });

  it("requires a parseable date in the future, within a year", () => {
    expect(expiryProblem("snoozed", "next week", NOW)).toMatch(/ISO 8601/);
    expect(expiryProblem("snoozed", inDays(-1), NOW)).toMatch(/future/);
    expect(expiryProblem("snoozed", inDays(366), NOW)).toMatch(/365 days/);
    expect(expiryProblem("snoozed", inDays(90), NOW)).toBeNull();
    expect(expiryProblem("accepted_risk", inDays(365), NOW)).toBeNull();
  });
});

describe("reasonLength", () => {
  it("counts characters the way Postgres does, not UTF-16 units", () => {
    expect(reasonLength("ok👍")).toBe(3);
    expect("ok👍".length).toBe(4);
  });
});

describe("loaders", () => {
  function client(result: { data: unknown; error: { code?: string; message: string } | null }, seen: string[] = []) {
    return {
      from: (table: string) => {
        seen.push(table);
        const b: Record<string, unknown> = {
          select: () => b,
          eq: (col: string, val: string) => (seen.push(`${col}=${val}`), b),
          then: (resolve: (v: unknown) => unknown) => Promise.resolve(result).then(resolve),
        };
        return b;
      },
    } as unknown as SupabaseClient;
  }

  it("loads one site's rows for one owner", async () => {
    const seen: string[] = [];
    const out = await loadTriageForHost(client({ data: [row("a")], error: null }, seen), "o1", "Shop.Example");
    expect(out).toMatchObject({ available: true, error: null });
    expect(out.rows).toHaveLength(1);
    expect(seen).toEqual(["finding_triage", "owner=o1", "target_host=shop.example"]);
  });

  it("reports unavailable, not an error, before migration 046", async () => {
    const out = await loadTriageForHost(client({ data: null, error: { code: "PGRST205", message: "no table" } }), "o1", "shop.example");
    expect(out).toEqual({ rows: [], available: false, error: null });
  });

  it("surfaces any other failure", async () => {
    const out = await loadTriageForHost(client({ data: null, error: { code: "57014", message: "timeout" } }), "o1", "shop.example");
    expect(out).toMatchObject({ available: true, error: "timeout" });
  });

  it("degrades to an empty index for scan-time callers", async () => {
    const failing = await loadTriageIndexForTarget(client({ data: null, error: { code: "57014", message: "timeout" } }), "o1", "https://shop.example/");
    expect(failing.host).toBe("shop.example");
    expect(failing.index.size).toBe(0);
    const ok = await loadTriageIndexForTarget(client({ data: [row("a")], error: null }), "o1", "https://shop.example/", NOW);
    expect(ok.index.get("shop.example", "a")).toBeDefined();
    expect((await loadTriageIndexForTarget(client({ data: [], error: null }), "o1", "nonsense")).host).toBeNull();
  });
});

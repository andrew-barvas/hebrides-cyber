import { describe, expect, it, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { PrioritisedFinding } from "./estatePriority";

const { loadViewMock, targetsMock, rankMock, sendEmailMock } = vi.hoisted(() => ({
  loadViewMock: vi.fn(),
  targetsMock: vi.fn(),
  rankMock: vi.fn(),
  sendEmailMock: vi.fn(),
}));
vi.mock("./findingsView", async (orig) => ({ ...(await orig<typeof import("./findingsView")>()), loadFindingsView: loadViewMock }));
vi.mock("./estatePriority", async (orig) => ({ ...(await orig<typeof import("./estatePriority")>()), loadTargetContexts: targetsMock, rankFindings: rankMock }));
vi.mock("./email", async (orig) => ({ ...(await orig<typeof import("./email")>()), sendEmail: sendEmailMock }));

import { buildWeeklyFixEmail, pickWeeklyFix, ratingStepFor, remediationFor, sendWeeklyFixEmails } from "./weeklyFixEmail";

const finding = (over: Partial<PrioritisedFinding> = {}): PrioritisedFinding =>
  ({
    key: "shop.example.com tls.expiring",
    host: "shop.example.com",
    checkId: "tls.cert-expiring-soon",
    checkBase: "tls.cert-expiring-soon",
    category: "tls",
    severity: "high",
    title: "Certificate expires in 9 days",
    detail: "Expires on 29 November.",
    scanId: "scan-1",
    triage: null,
    priority: { rank: 1, score: 9, base: 5, factors: [], reason: "High severity on your shop, expiring soon" },
    ...over,
  }) as unknown as PrioritisedFinding;

describe("pickWeeklyFix", () => {
  it("takes the top-ranked untriaged, non-info finding", () => {
    const triaged = finding({ key: "a", triage: { state: "snoozed", reason: "x", expiresAt: null } });
    const info = finding({ key: "b", severity: "info" });
    expect(pickWeeklyFix([triaged, info, finding({ key: "c" })])?.key).toBe("c");
    expect(pickWeeklyFix([])).toBeNull();
  });
});

describe("remediationFor", () => {
  it("reads the stored remediation from the latest scan of that site", () => {
    const detail = new Map([["shop.example.com", { scanId: "s", findings: [{ checkId: "tls.cert-expiring-soon", remediation: "Renew it." } as never] }]]);
    expect(remediationFor(detail, "shop.example.com", "tls.cert-expiring-soon")).toBe("Renew it.");
    expect(remediationFor(detail, "shop.example.com", "other")).toBeNull();
  });
});

describe("ratingStepFor", () => {
  const detail = (score: number | null | undefined, findings: Array<{ checkId: string; severity: string }>) => ({ scanId: "s", score, findings });
  // 100 - 30 - 15 - 7 = 48: At risk; Needs attention is 50+.
  const findings = [
    { checkId: "crit", severity: "critical" },
    { checkId: "high", severity: "high" },
    { checkId: "med", severity: "medium" },
  ];
  const open = new Set(["crit", "high", "med"]);

  it("counts the fixes, starting with this week's, to the next rating", () => {
    expect(ratingStepFor(detail(48, findings), open, "med")).toEqual({ fixes: 1, fromLabel: "At risk", toLabel: "Needs attention" });
    expect(ratingStepFor(detail(60, [{ checkId: "low", severity: "low" }, ...findings]), new Set(["low", "crit"]), "low")).toEqual({ fixes: 2, fromLabel: "Needs attention", toLabel: "Good" });
  });

  it("is null with no stored score, at Strong, when this week's isn't open, or when the next rating is out of reach", () => {
    expect(ratingStepFor(detail(null, findings), open, "med")).toBeNull();
    expect(ratingStepFor(detail(undefined, findings), open, "med")).toBeNull();
    expect(ratingStepFor(detail(95, findings), open, "med")).toBeNull();
    expect(ratingStepFor(undefined, open, "med")).toBeNull();
    expect(ratingStepFor(detail(48, findings), new Set(["crit"]), "med")).toBeNull();
    expect(ratingStepFor(detail(20, [{ checkId: "low", severity: "low" }]), new Set(["low"]), "low")).toBeNull();
  });
});

describe("buildWeeklyFixEmail", () => {
  const base = { finding: finding(), remediation: "**On WordPress:** renew in the dashboard.\n<script>x</script>", openCount: 4, last: null, siteUrl: "https://www.hebridescyber.co.uk" };

  it("names one finding, why, how to fix it (escaped), and links to its report", () => {
    const { subject, html } = buildWeeklyFixEmail(base);
    expect(subject).toBe("One thing to fix this week: Certificate expires in 9 days");
    expect(html).toContain("High severity on your shop, expiring soon");
    expect(html).toContain("<b>On WordPress:</b> renew in the dashboard.<br>&lt;script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain('href="https://www.hebridescyber.co.uk/dashboard/scans/scan-1"');
    expect(html).toContain("3 other open issues can wait");
    expect(html).toContain("/dashboard/integrations");
  });

  it("says how many fixes lift the site to the next rating, when known", () => {
    expect(buildWeeklyFixEmail({ ...base, ratingStep: { fixes: 1, fromLabel: "Needs attention", toLabel: "Good" } }).html).toContain("<b>Fixing this one</b> should take shop.example.com from Needs attention to Good.");
    expect(buildWeeklyFixEmail({ ...base, ratingStep: { fixes: 3, fromLabel: "At risk", toLabel: "Needs attention" } }).html).toContain("<b>Fixing this and 2 more</b> should take shop.example.com from At risk to Needs attention.");
    expect(buildWeeklyFixEmail(base).html).not.toContain("should take");
  });

  it("says when last week's is fixed, or that it's still the same one", () => {
    expect(buildWeeklyFixEmail({ ...base, last: { host: "x", checkId: "y", title: "Missing HSTS", fixed: true } }).html).toContain("Last week's is fixed:</b> Missing HSTS");
    expect(buildWeeklyFixEmail({ ...base, last: { host: "shop.example.com", checkId: "tls.cert-expiring-soon", title: "t", fixed: false } }).html).toContain("still last week's suggestion");
  });
});

describe("sendWeeklyFixEmails", () => {
  type Sub = Record<string, unknown>;
  let subs: Sub[];
  let updates: Array<Record<string, unknown>>;
  const db = () =>
    ({
      from: (table: string) => {
        const q: Record<string, unknown> = {
          select: () => q,
          eq: () => q,
          maybeSingle: async () => ({ data: { email: "owner@example.com" }, error: null }),
          update: (row: Record<string, unknown>) => {
            updates.push(row);
            return { eq: async () => ({ error: null }) };
          },
          then: (r: (v: unknown) => void) => r(table === "subscriptions" ? { data: subs, error: null } : { data: [], error: null }),
        };
        return q;
      },
    }) as unknown as SupabaseClient;

  beforeEach(() => {
    updates = [];
    subs = [{ owner: "o1", notify_weekly_fix: true, weekly_fix_sent_at: null, weekly_fix_host: "shop.example.com", weekly_fix_check_id: "headers.hsts", weekly_fix_title: "Missing HSTS" }];
    loadViewMock.mockReset().mockResolvedValue({ ok: true, data: { rows: [], detailByHost: new Map() } });
    targetsMock.mockReset().mockResolvedValue({ contexts: new Map() });
    rankMock.mockReset().mockReturnValue([finding()]);
    sendEmailMock.mockReset().mockResolvedValue({ ok: true });
  });

  it("sends one email, says last week's is fixed, and remembers this week's", async () => {
    const r = await sendWeeklyFixEmails(db(), { now: new Date("2026-11-23T08:00:00Z"), siteUrl: "https://www.hebridescyber.co.uk" });
    expect(r).toEqual({ sent: 1, skipped: 0, errors: [] });
    expect(sendEmailMock.mock.calls[0][0].to).toBe("owner@example.com");
    expect(sendEmailMock.mock.calls[0][0].html).toContain("Last week's is fixed:</b> Missing HSTS");
    expect(updates[0]).toMatchObject({ weekly_fix_host: "shop.example.com", weekly_fix_check_id: "tls.cert-expiring-soon", weekly_fix_sent_at: "2026-11-23T08:00:00.000Z" });
  });

  it("skips anyone opted out, sent in the last six days, or with nothing worth fixing", async () => {
    subs = [
      { owner: "a", notify_weekly_fix: false },
      { owner: "b", notify_weekly_fix: true, weekly_fix_sent_at: "2026-11-20T08:00:00Z" },
    ];
    expect(await sendWeeklyFixEmails(db(), { now: new Date("2026-11-23T08:00:00Z") })).toEqual({ sent: 0, skipped: 2, errors: [] });
    subs = [{ owner: "c", notify_weekly_fix: true }];
    rankMock.mockReturnValue([]);
    expect(await sendWeeklyFixEmails(db(), { now: new Date("2026-11-23T08:00:00Z") })).toEqual({ sent: 0, skipped: 1, errors: [] });
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("adds the rating line from the site's latest score and open findings", async () => {
    loadViewMock.mockResolvedValue({ ok: true, data: { rows: [], detailByHost: new Map([["shop.example.com", { scanId: "scan-1", score: 85, findings: [{ checkId: "tls.cert-expiring-soon", severity: "high" }] }]]) } });
    await sendWeeklyFixEmails(db(), { now: new Date("2026-11-23T08:00:00Z") });
    expect(sendEmailMock.mock.calls[0][0].html).toContain("from Good to Strong");
  });

  it("reports a failed send as an error and doesn't record it as sent", async () => {
    sendEmailMock.mockResolvedValue({ ok: false, error: "RESEND_API_KEY not configured" });
    const r = await sendWeeklyFixEmails(db(), { now: new Date("2026-11-23T08:00:00Z") });
    expect(r.errors).toEqual(["o1: RESEND_API_KEY not configured"]);
    expect(updates).toEqual([]);
  });
});

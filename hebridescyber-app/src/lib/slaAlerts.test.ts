import { describe, it, expect, vi, beforeEach } from "vitest";

const { sendEmailMock } = vi.hoisted(() => ({ sendEmailMock: vi.fn() }));
vi.mock("./email", async (orig) => ({ ...(await orig<typeof import("./email")>()), sendEmail: sendEmailMock }));

import { buildSlaAlertEmail, sendSlaAlerts } from "./slaAlerts";
import type { SlaItem } from "./slaMonitoring";

const NOW = new Date("2026-09-27T12:00:00Z");
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();

type Tables = Record<string, { data: unknown; error?: { code?: string; message: string } | null }>;
let tables: Tables;
let updates: Array<{ values: Record<string, unknown>; ids: string[] }>;

function makeClient() {
  return {
    from: (table: string) => {
      const b: Record<string, unknown> = {};
      for (const m of ["select", "eq", "is"]) b[m] = () => b;
      const result = () => Promise.resolve({ data: tables[table]?.data ?? null, error: tables[table]?.error ?? null });
      b.maybeSingle = result;
      b.then = (resolve: (v: unknown) => unknown) => result().then(resolve);
      b.update = (values: Record<string, unknown>) => ({
        in: (_col: string, ids: string[]) => {
          updates.push({ values, ids });
          return Promise.resolve({ error: null });
        },
      });
      return b;
    },
  } as never;
}

const lifecycle = (id: string, severity: string, firstSeenDaysAgo: number, extra: Record<string, unknown> = {}) => ({
  id, target_host: "shop.example", check_id: `c.${id}`, severity, title: `Finding ${id}`,
  first_seen_at: daysAgo(firstSeenDaysAgo), last_seen_at: daysAgo(0), resolved_at: null,
  sla_warned_at: null, sla_breach_notified_at: null, ...extra,
});

beforeEach(() => {
  sendEmailMock.mockReset().mockResolvedValue({ ok: true });
  updates = [];
  tables = {
    subscriptions: { data: { plan: "agency", status: "active" } },
    users: { data: { is_admin: false, email: "owner@agency.example" } },
    sla_policies: { data: null },
    finding_lifecycle: {
      data: [
        lifecycle("late", "critical", 20), // 15-day SLA → breached
        lifecycle("soon", "high", 28), // 30-day SLA, 3-day warning → due soon
        lifecycle("fine", "medium", 10),
      ],
    },
  };
});

describe("sendSlaAlerts", () => {
  it("emails newly due-soon and breached findings, then marks them", async () => {
    await sendSlaAlerts(makeClient(), "o1", "shop.example", NOW);
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    const { to, subject, html } = sendEmailMock.mock.calls[0][0];
    expect(to).toBe("owner@agency.example");
    expect(subject).toBe("1 finding past remediation SLA on shop.example");
    expect(html).toContain("Finding late");
    expect(html).toContain("Finding soon");
    expect(html).not.toContain("Finding fine");
    expect(updates).toEqual([
      { values: { sla_breach_notified_at: NOW.toISOString() }, ids: ["late"] },
      { values: { sla_warned_at: NOW.toISOString() }, ids: ["soon"] },
    ]);
  });

  it("stays quiet for findings already alerted at their current stage", async () => {
    tables.finding_lifecycle.data = [lifecycle("late", "critical", 20, { sla_breach_notified_at: daysAgo(1) })];
    await sendSlaAlerts(makeClient(), "o1", "shop.example", NOW);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("is Agency-only", async () => {
    tables.subscriptions.data = { plan: "pro", status: "active" };
    await sendSlaAlerts(makeClient(), "o1", "shop.example", NOW);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("lets admins through regardless of plan", async () => {
    tables.subscriptions.data = null;
    tables.users.data = { is_admin: true, email: "admin@example.com" };
    await sendSlaAlerts(makeClient(), "o1", "shop.example", NOW);
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
  });

  it("respects an account that turned alerts off", async () => {
    tables.sla_policies.data = { critical_days: 15, high_days: 30, medium_days: 90, low_days: 180, warn_days: 3, alerts_enabled: false };
    await sendSlaAlerts(makeClient(), "o1", "shop.example", NOW);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  // Marking undelivered alerts would swallow them for good.
  it("doesn't mark anything when the email fails", async () => {
    sendEmailMock.mockResolvedValue({ ok: false, error: "RESEND_API_KEY not configured" });
    await sendSlaAlerts(makeClient(), "o1", "shop.example", NOW);
    expect(updates).toEqual([]);
  });

  it("skips findings the owner has triaged, and works before migration 046", async () => {
    tables.finding_triage = {
      data: [{
        id: "t1", owner: "o1", target_host: "shop.example", check_id: "c.late", state: "accepted_risk", reason: "Compensating control",
        expires_at: null, created_by: "o1", created_at: daysAgo(2), updated_at: daysAgo(2),
      }],
    };
    await sendSlaAlerts(makeClient(), "o1", "shop.example", NOW);
    expect(sendEmailMock.mock.calls[0][0].html).not.toContain("Finding late");
    expect(updates).toEqual([{ values: { sla_warned_at: NOW.toISOString() }, ids: ["soon"] }]);

    sendEmailMock.mockClear();
    updates = [];
    tables.finding_triage = { data: null, error: { code: "PGRST205", message: "Could not find the table" } };
    await sendSlaAlerts(makeClient(), "o1", "shop.example", NOW);
    expect(sendEmailMock.mock.calls[0][0].html).toContain("Finding late");
  });

  it("holds off when triage can't be read, rather than alert on accepted findings", async () => {
    tables.finding_triage = { data: null, error: { code: "57014", message: "statement timeout" } };
    await sendSlaAlerts(makeClient(), "o1", "shop.example", NOW);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("does nothing before migration 043", async () => {
    tables.finding_lifecycle = { data: null, error: { code: "42P01", message: "relation does not exist" } };
    await expect(sendSlaAlerts(makeClient(), "o1", "shop.example", NOW)).resolves.toBeUndefined();
    expect(sendEmailMock).not.toHaveBeenCalled();
  });
});

describe("buildSlaAlertEmail", () => {
  const item = (id: string, state: SlaItem["state"], daysRemaining: number, title = `T ${id}`): SlaItem => ({
    id, host: "shop.example", checkId: id, severity: "high", title, firstSeenAt: daysAgo(10), dueAt: daysAgo(0), daysRemaining, state,
  });

  it("uses a due-soon subject when nothing has breached", () => {
    expect(buildSlaAlertEmail("shop.example", { dueSoon: [item("a", "due_soon", 2), item("b", "due_soon", 1)], breached: [] }, "x").subject).toBe(
      "2 findings nearing remediation SLA on shop.example"
    );
  });

  it("escapes finding titles taken from scanned sites", () => {
    const { html } = buildSlaAlertEmail("shop.example", { dueSoon: [], breached: [item("a", "breached", -2, "<script>x</script>")] }, "x");
    expect(html).not.toContain("<script>x");
    expect(html).toContain("2 days overdue");
  });

  it("caps the table at 20 rows and says how many more", () => {
    const many = Array.from({ length: 23 }, (_, i) => item(String(i), "breached", -1));
    expect(buildSlaAlertEmail("shop.example", { dueSoon: [], breached: many }, "x").html).toContain("and 3 more");
  });
});

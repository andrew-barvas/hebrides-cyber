import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  deliverReportEmail,
  gatherReportData,
  markReportSent,
  runDueReport,
  type PlanCheck,
  type ScheduledReport,
  type SendReportEmail,
} from "./scheduledReports";
import type { TriageDbRow } from "./findingTriage";

// A table-keyed fake of the Supabase query builder: every chained call returns
// the builder, and awaiting it (or .maybeSingle()) takes the next queued
// response for that table.
type FakeResponse = { data?: unknown; error?: { code?: string; message: string } | null };
let queues: Record<string, FakeResponse[]> = {};
let updates: Record<string, unknown>[] = [];
let reads: string[] = [];

function builder(table: string) {
  const next = () => {
    reads.push(table);
    return Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  };
  const b: Record<string, unknown> = {
    select: () => b,
    eq: () => b,
    order: () => b,
    limit: () => b,
    update: (row: Record<string, unknown>) => {
      updates.push(row);
      return b;
    },
    maybeSingle: next,
    then: (resolve: (v: unknown) => void, reject: (e: unknown) => void) => next().then(resolve, reject),
  };
  return b;
}

const db = { from: (table: string) => builder(table) } as unknown as SupabaseClient;

const NOW = new Date("2026-10-30T00:15:00Z");
const OWNER = "55555555-5555-5555-5555-555555555555";
const SITE = "https://shop.example.co.uk";

const triageRow = (check_id: string, state: TriageDbRow["state"], expires_at: string | null = null): TriageDbRow => ({
  id: `t-${check_id}`,
  owner: OWNER,
  target_host: "shop.example.co.uk",
  check_id,
  state,
  reason: "reviewed",
  expires_at,
  created_by: OWNER,
  created_at: "2026-10-01T00:00:00Z",
  updated_at: "2026-10-01T00:00:00Z",
});

const finding = (checkId: string, severity: string) => ({ checkId, severity, title: checkId });

/** One monitored site with a completed scan and the given findings. */
function queueOneSite(findings: unknown[], triage: TriageDbRow[] = []) {
  queues.monitored_targets = [{ data: [{ target_url: SITE }] }];
  queues.finding_triage = [{ data: triage }];
  queues.scans = [{ data: { id: "scan-1", score: 64, created_at: "2026-10-29T03:00:00Z" } }];
  queues.scan_results = [{ data: { results: { findings } } }];
}

beforeEach(() => {
  queues = {};
  updates = [];
  reads = [];
});

describe("gatherReportData", () => {
  it("counts only open findings: false positives and active accepted or snoozed risks are left out", async () => {
    queueOneSite(
      [finding("a", "high"), finding("b", "high"), finding("c", "medium"), finding("d", "low"), finding("e", "low"), finding("f", "info")],
      [
        triageRow("a", "false_positive"),
        triageRow("b", "snoozed", "2026-11-15T00:00:00Z"), // still snoozed
        triageRow("c", "accepted_risk"),
        triageRow("d", "snoozed", "2026-10-01T00:00:00Z"), // snooze ended: counts again
      ],
    );

    const [summary] = await gatherReportData(db, OWNER, null, NOW);

    expect(summary).toEqual({
      targetUrl: SITE,
      totalFindings: 3, // d, e and f: two low and one info
      critical: 0,
      high: 0,
      medium: 0,
      low: 2,
      info: 1,
      score: 64,
      lastScanDate: "2026-10-29T03:00:00Z",
    });
  });

  it("matches triage by hostname, however the monitored URL is written", async () => {
    queues.monitored_targets = [{ data: [{ target_url: "https://SHOP.example.co.uk/path" }] }];
    queues.finding_triage = [{ data: [triageRow("a", "false_positive")] }];
    queues.scans = [{ data: { id: "scan-1", score: 90, created_at: "2026-10-29T03:00:00Z" } }];
    queues.scan_results = [{ data: { results: { findings: [finding("a", "critical"), finding("b", "high")] } } }];

    const [summary] = await gatherReportData(db, OWNER, null, NOW);

    expect(summary.critical).toBe(0);
    expect(summary.high).toBe(1);
  });

  it("carries on with nothing triaged when the triage table doesn't exist yet", async () => {
    queueOneSite([finding("a", "high")]);
    queues.finding_triage = [{ data: null, error: { code: "42P01", message: 'relation "finding_triage" does not exist' } }];

    const [summary] = await gatherReportData(db, OWNER, null, NOW);

    expect(summary.high).toBe(1);
  });

  it("reports a site with no completed scan as having no results, not as clean", async () => {
    queueOneSite([]);
    queues.scans = [{ data: null }];

    expect(await gatherReportData(db, OWNER, null, NOW)).toEqual([
      { targetUrl: SITE, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, score: null, lastScanDate: null },
    ]);
  });

  it("reports a completed scan with no stored results as having no results, not as zero findings", async () => {
    queueOneSite([]);
    queues.scan_results = [{ data: null }];

    const [summary] = await gatherReportData(db, OWNER, null, NOW);

    expect(summary.lastScanDate).toBeNull();
    expect(summary.score).toBeNull();
    expect(summary.totalFindings).toBe(0);
  });

  it("returns nothing, without reading triage, when the account has no monitored sites", async () => {
    queues.monitored_targets = [{ data: [] }];

    expect(await gatherReportData(db, OWNER, null, NOW)).toEqual([]);
    expect(reads).toEqual(["monitored_targets"]);
  });

  it.each([
    ["monitored sites", "monitored_targets", /Could not read monitored sites: db down/],
    ["triage decisions", "finding_triage", /Could not read triage decisions: db down/],
    ["the latest scan", "scans", new RegExp(`Could not read the latest scan for ${SITE}: db down`)],
    ["scan results", "scan_results", new RegExp(`Could not read scan results for ${SITE}: db down`)],
  ])("throws when reading %s fails, rather than reporting an empty or clean site", async (_what, table, message) => {
    queueOneSite([finding("a", "high")]);
    queues[table] = [{ data: null, error: { code: "500", message: "db down" } }];

    await expect(gatherReportData(db, OWNER, null, NOW)).rejects.toThrow(message);
  });
});

describe("markReportSent", () => {
  it("records the send and the next due date", async () => {
    await markReportSent(db, "r1", "weekly", NOW);

    expect(updates).toEqual([{ last_sent: NOW.toISOString(), next_due: "2026-11-06T00:15:00.000Z", updated_at: NOW.toISOString() }]);
  });

  it("throws when the update fails, because the report would otherwise go out again next run", async () => {
    queues.scheduled_reports = [{ error: { message: "write failed" } }];

    await expect(markReportSent(db, "r1", "daily", NOW)).rejects.toThrow(/could not record it .* write failed/);
  });
});

describe("deliverReportEmail", () => {
  const email = { subject: "S", html: "<p>h</p>", attachments: [{ filename: "r.pdf", content: Buffer.from("%PDF") }] };

  it("sends to each recipient separately, with the attachments, and says who got it", async () => {
    const send = vi.fn<SendReportEmail>(async () => ({ ok: true }));

    const delivery = await deliverReportEmail(["a@example.com", "b@example.com"], email, send);

    expect(delivery).toEqual({ delivered: ["a@example.com", "b@example.com"], failed: [] });
    expect(send).toHaveBeenCalledTimes(2);
    expect(send).toHaveBeenCalledWith({ to: "a@example.com", subject: "S", html: "<p>h</p>", attachments: email.attachments });
  });

  it("records a { ok: false } result as a failure, which the sender used to ignore", async () => {
    const send = vi.fn<SendReportEmail>(async ({ to }) => (to === "bad@example.com" ? { ok: false, error: "Resend responded 422" } : { ok: true }));

    const delivery = await deliverReportEmail(["a@example.com", "bad@example.com"], email, send);

    expect(delivery.delivered).toEqual(["a@example.com"]);
    expect(delivery.failed).toEqual([{ recipient: "bad@example.com", error: "Resend responded 422" }]);
  });

  it("records a thrown error, and a failure with no message, without stopping the others", async () => {
    const send = vi.fn<SendReportEmail>(async ({ to }) => {
      if (to === "throws@example.com") throw new Error("socket hang up");
      if (to === "silent@example.com") return { ok: false };
      return { ok: true };
    });

    const delivery = await deliverReportEmail(["throws@example.com", "silent@example.com", "a@example.com"], email, send);

    expect(delivery.delivered).toEqual(["a@example.com"]);
    expect(delivery.failed).toEqual([
      { recipient: "throws@example.com", error: "socket hang up" },
      { recipient: "silent@example.com", error: "unknown error" },
    ]);
  });
});

describe("runDueReport", () => {
  const report: ScheduledReport = {
    id: "r1",
    owner: OWNER,
    target_url: null,
    frequency: "weekly",
    format: "csv",
    recipients: ["a@example.com", "b@example.com"],
    enabled: true,
    last_sent: null,
    next_due: "2026-10-30T00:00:00Z",
  };
  const renderPdf = vi.fn<(html: string) => Promise<Buffer>>(async () => Buffer.from("%PDF-1.7"));
  const send = vi.fn<SendReportEmail>();
  const planCheck = vi.fn<(ownerId: string) => Promise<PlanCheck>>();
  const run = (r: ScheduledReport = report) => runDueReport(db, r, { siteUrl: "https://www.hebridescyber.co.uk", renderPdf, send, planCheck, now: NOW });

  beforeEach(() => {
    renderPdf.mockClear();
    send.mockReset().mockResolvedValue({ ok: true });
    planCheck.mockReset().mockResolvedValue("ok");
  });

  it("sends the report and marks it sent", async () => {
    queueOneSite([finding("a", "high")]);

    const outcome = await run();

    expect(outcome).toEqual({ kind: "sent", delivered: ["a@example.com", "b@example.com"], failed: [], sentFormat: "csv", pdfError: undefined });
    expect(planCheck).toHaveBeenCalledWith(OWNER);
    expect(send).toHaveBeenCalledTimes(2);
    expect(updates).toEqual([{ last_sent: NOW.toISOString(), next_due: "2026-11-06T00:15:00.000Z", updated_at: NOW.toISOString() }]);
  });

  it("attaches the PDF for a pdf report", async () => {
    queueOneSite([finding("a", "high")]);

    await run({ ...report, format: "pdf" });

    expect(renderPdf).toHaveBeenCalledTimes(1);
    expect(send.mock.calls[0][0].attachments).toEqual([{ filename: "hebridescyber-report-2026-10-30.pdf", content: Buffer.from("%PDF-1.7") }]);
  });

  it("does not mark the report sent when nobody received it, so the next run retries", async () => {
    queueOneSite([finding("a", "high")]);
    send.mockResolvedValue({ ok: false, error: "RESEND_API_KEY not configured" });

    const outcome = await run();

    expect(outcome).toEqual({
      kind: "undelivered",
      failed: [
        { recipient: "a@example.com", error: "RESEND_API_KEY not configured" },
        { recipient: "b@example.com", error: "RESEND_API_KEY not configured" },
      ],
    });
    expect(updates).toEqual([]);
  });

  it("marks it sent when at least one recipient got it, and lists the one who didn't", async () => {
    queueOneSite([finding("a", "high")]);
    send.mockImplementation(async ({ to }) => (to === "b@example.com" ? { ok: false, error: "bounced" } : { ok: true }));

    const outcome = await run();

    expect(outcome).toMatchObject({ kind: "sent", delivered: ["a@example.com"], failed: [{ recipient: "b@example.com", error: "bounced" }] });
    expect(updates).toHaveLength(1);
  });

  it("skips an owner without an active paid plan: nothing read, rendered, sent or recorded", async () => {
    planCheck.mockResolvedValue("denied");

    expect(await run({ ...report, format: "pdf" })).toEqual({ kind: "not_entitled" });
    expect(reads).toEqual([]);
    expect(renderPdf).not.toHaveBeenCalled();
    expect(send).not.toHaveBeenCalled();
    expect(updates).toEqual([]);
  });

  it("throws, sending nothing, when the plan can't be read: that is not the same as a lapsed plan", async () => {
    planCheck.mockResolvedValue("error");

    await expect(run()).rejects.toThrow("Could not check the owner's plan");
    expect(send).not.toHaveBeenCalled();
    expect(updates).toEqual([]);
  });

  it("skips an account with no monitored sites, leaving the report due", async () => {
    queues.monitored_targets = [{ data: [] }];

    expect(await run()).toEqual({ kind: "no_sites" });
    expect(send).not.toHaveBeenCalled();
    expect(updates).toEqual([]);
  });

  it("throws, sending nothing, when a lookup fails", async () => {
    queueOneSite([finding("a", "high")]);
    queues.scan_results = [{ data: null, error: { message: "db down" } }];

    await expect(run()).rejects.toThrow(/Could not read scan results/);
    expect(send).not.toHaveBeenCalled();
    expect(updates).toEqual([]);
  });

  it("throws when the send worked but recording it failed, so the duplicate next run is reported", async () => {
    queueOneSite([finding("a", "high")]);
    queues.scheduled_reports = [{ error: { message: "write failed" } }];

    await expect(run()).rejects.toThrow(/could not record it/);
    expect(send).toHaveBeenCalledTimes(2);
  });
});

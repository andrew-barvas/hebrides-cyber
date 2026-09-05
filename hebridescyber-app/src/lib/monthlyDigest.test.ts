import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { sendMonthlyDigest } from "./monthlyDigest";
import type { Finding } from "./scanners";

const { sendEmailMock } = vi.hoisted(() => ({ sendEmailMock: vi.fn() }));

vi.mock("./email", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./email")>();
  return { ...actual, sendEmail: sendEmailMock };
});

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    gte: () => builder,
    order: () => builder,
    maybeSingle: next,
    then: (resolve: (v: unknown) => void, reject?: (e: unknown) => void) => next().then(resolve, reject),
  };
  return builder;
}

function fakeSupabase(): SupabaseClient {
  return { from: (table: string) => makeBuilder(table) } as unknown as SupabaseClient;
}

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  severity: "medium",
  title: "Missing header",
  detail: "detail",
  checkId: "headers.missing",
  ...overrides,
});

const DAYS = 24 * 60 * 60 * 1000;
const now = Date.now();

describe("sendMonthlyDigest", () => {
  beforeEach(() => {
    queues = {};
    sendEmailMock.mockReset().mockResolvedValue({ ok: true });
  });

  it("throws if the active-subscriptions query itself errors", async () => {
    queues.subscriptions = [{ data: null, error: { message: "connection refused" } }];
    await expect(sendMonthlyDigest(fakeSupabase())).rejects.toThrow("connection refused");
  });

  it("skips an owner with no monitored targets, without querying further", async () => {
    queues.subscriptions = [{ data: [{ owner: "owner-1" }], error: null }];
    queues.monitored_targets = [{ data: [], error: null }];

    const result = await sendMonthlyDigest(fakeSupabase());

    expect(result).toEqual({ ok: true, sent: 0, skipped: 1, errors: [] });
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("skips an owner with no email on file", async () => {
    queues.subscriptions = [{ data: [{ owner: "owner-1" }], error: null }];
    queues.monitored_targets = [{ data: [{ target_url: "https://example.com" }], error: null }];
    queues.users = [{ data: null, error: null }];

    const result = await sendMonthlyDigest(fakeSupabase());

    expect(result).toEqual({ ok: true, sent: 0, skipped: 1, errors: [] });
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("skips an owner with no completed scans in the lookback window", async () => {
    queues.subscriptions = [{ data: [{ owner: "owner-1" }], error: null }];
    queues.monitored_targets = [{ data: [{ target_url: "https://example.com" }], error: null }];
    queues.users = [{ data: { email: "jo@example.com" }, error: null }];
    queues.scans = [{ data: [], error: null }];

    const result = await sendMonthlyDigest(fakeSupabase());

    expect(result).toEqual({ ok: true, sent: 0, skipped: 1, errors: [] });
  });

  it("sends a digest with a score delta and new/fixed counts when a valid comparison scan exists", async () => {
    queues.subscriptions = [{ data: [{ owner: "owner-1" }], error: null }];
    queues.monitored_targets = [{ data: [{ target_url: "https://example.com" }], error: null }];
    queues.users = [{ data: { email: "jo@example.com" }, error: null }];
    queues.scans = [
      {
        data: [
          {
            id: "scan-latest",
            target_url: "https://example.com",
            created_at: new Date(now).toISOString(),
            scan_results: [
              { results: { findings: [finding({ checkId: "headers.missing" })] }, score: 80, created_at: new Date(now).toISOString() },
            ],
          },
          {
            id: "scan-old",
            target_url: "https://example.com",
            created_at: new Date(now - 25 * DAYS).toISOString(),
            scan_results: [
              {
                results: { findings: [finding({ checkId: "headers.missing" }), finding({ checkId: "tls.expired" })] },
                score: 60,
                created_at: new Date(now - 25 * DAYS).toISOString(),
              },
            ],
          },
        ],
        error: null,
      },
    ];

    const result = await sendMonthlyDigest(fakeSupabase());

    expect(result).toEqual({ ok: true, sent: 1, skipped: 0, errors: [] });
    expect(sendEmailMock).toHaveBeenCalledTimes(1);
    const call = sendEmailMock.mock.calls[0][0];
    expect(call.to).toBe("jo@example.com");
    expect(call.html).toContain("example.com");
    expect(call.html).toContain("80/100 (+20)");
    // headers.missing persisted (unchanged), tls.expired resolved (fixed), nothing new.
    expect(call.html).toContain("0 new");
    expect(call.html).toContain("1 fixed");
  });

  it("does not compute a delta when no scan is old enough to count as a real comparison", async () => {
    queues.subscriptions = [{ data: [{ owner: "owner-1" }], error: null }];
    queues.monitored_targets = [{ data: [{ target_url: "https://example.com" }], error: null }];
    queues.users = [{ data: { email: "jo@example.com" }, error: null }];
    queues.scans = [
      {
        data: [
          {
            id: "scan-latest",
            target_url: "https://example.com",
            created_at: new Date(now).toISOString(),
            scan_results: [{ results: { findings: [] }, score: 90, created_at: new Date(now).toISOString() }],
          },
          {
            id: "scan-too-recent",
            target_url: "https://example.com",
            created_at: new Date(now - 2 * DAYS).toISOString(),
            scan_results: [{ results: { findings: [] }, score: 70, created_at: new Date(now - 2 * DAYS).toISOString() }],
          },
        ],
        error: null,
      },
    ];

    await sendMonthlyDigest(fakeSupabase());

    const call = sendEmailMock.mock.calls[0][0];
    expect(call.html).toContain("no prior scan to compare");
    expect(call.html).not.toContain("(+");
  });

  it("records a per-owner error and keeps processing the remaining owners", async () => {
    queues.subscriptions = [{ data: [{ owner: "owner-1" }, { owner: "owner-2" }], error: null }];
    queues.monitored_targets = [
      { data: [{ target_url: "https://a.example.com" }], error: null },
      { data: [{ target_url: "https://b.example.com" }], error: null },
    ];
    queues.users = [
      { data: { email: "a@example.com" }, error: null },
      { data: { email: "b@example.com" }, error: null },
    ];
    queues.scans = [
      {
        data: [
          {
            id: "scan-a",
            target_url: "https://a.example.com",
            created_at: new Date(now).toISOString(),
            scan_results: [{ results: { findings: [] }, score: 100, created_at: new Date(now).toISOString() }],
          },
        ],
        error: null,
      },
      {
        data: [
          {
            id: "scan-b",
            target_url: "https://b.example.com",
            created_at: new Date(now).toISOString(),
            scan_results: [{ results: { findings: [] }, score: 100, created_at: new Date(now).toISOString() }],
          },
        ],
        error: null,
      },
    ];
    sendEmailMock.mockResolvedValueOnce({ ok: false, error: "Resend responded 500" }).mockResolvedValueOnce({ ok: true });

    const result = await sendMonthlyDigest(fakeSupabase());

    expect(result.sent).toBe(1);
    expect(result.skipped).toBe(0);
    expect(result.errors).toEqual(["owner-1: Resend responded 500"]);
  });
});

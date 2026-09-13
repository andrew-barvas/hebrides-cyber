import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const {
  authenticateApiRequestMock,
  checkRateLimitMock,
  triggerOnDemandWorkflowMock,
  validateNoSsrfMock,
  isDomainVerifiedMock,
} = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  checkRateLimitMock: vi.fn(),
  triggerOnDemandWorkflowMock: vi.fn(),
  validateNoSsrfMock: vi.fn(),
  isDomainVerifiedMock: vi.fn(),
}));

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};
const inserted: Array<{ table: string; payload: unknown }> = [];

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    update: () => builder,
    maybeSingle: next,
    single: next,
    insert: (payload: unknown) => {
      inserted.push({ table, payload });
      return builder;
    },
    then: (resolve: (v: unknown) => void) => next().then(resolve),
  };
  return builder;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (table: string) => makeBuilder(table) },
}));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: checkRateLimitMock }));
vi.mock("@/lib/onDemandScanTrigger", () => ({ triggerOnDemandWorkflow: triggerOnDemandWorkflowMock }));
vi.mock("@/lib/ownership", () => ({
  validateNoSsrf: validateNoSsrfMock,
  isDomainVerified: isDomainVerifiedMock,
}));

import handler from "@/pages/api/scans/[id]/replay";

const OWNER_ID = "owner-1";
const SCAN_ID = "scan-1";
const TARGET_URL = "https://example.com";

function mockReqRes() {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "POST", query: { id: SCAN_ID } });
}

describe("POST /api/scans/[id]/replay", () => {
  beforeEach(() => {
    queues = {};
    inserted.length = 0;
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
    checkRateLimitMock.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
    triggerOnDemandWorkflowMock.mockReset().mockResolvedValue(undefined);
    validateNoSsrfMock.mockReset().mockResolvedValue(TARGET_URL);
    isDomainVerifiedMock.mockReset().mockResolvedValue(true);
  });

  it("returns 405 for non-POST", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 401 when unauthenticated", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 429 when rate-limited, before touching scans", async () => {
    checkRateLimitMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 12 });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(429);
    expect(res._getHeaders()["retry-after"]).toBe("12");
    expect(inserted).toEqual([]);
  });

  it("returns 404 when the scan doesn't exist", async () => {
    queues.scans = [{ data: null }];
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);
  });

  it("returns 403 when the caller doesn't own the scan and isn't on the owner's team", async () => {
    queues.scans = [{ data: { id: SCAN_ID, owner: "someone-else", target_url: TARGET_URL } }];
    queues.teams = [{ data: null, error: null }];
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("allows a team 'developer' to replay on the owner's behalf, attributing the new scan to the owner", async () => {
    const teamOwnerId = "someone-else";
    queues.scans = [{ data: { id: SCAN_ID, owner: teamOwnerId, target_url: TARGET_URL } }];
    queues.teams = [{ data: { id: "team-1" }, error: null }];
    queues.team_members = [{ data: { role: "developer" }, error: null }];
    queues.monitored_targets = [{ data: { scan_profile: "safe" }, error: null }];
    queues.scans.push({ data: { id: "new-scan-1" }, error: null });
    queues.scan_jobs = [{ data: null, error: null }];

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(202);
    const scansInsert = inserted.find((i) => i.table === "scans");
    expect(scansInsert?.payload).toMatchObject({ owner: teamOwnerId });
    const jobInsert = inserted.find((i) => i.table === "scan_jobs");
    expect(jobInsert?.payload).toMatchObject({ owner: teamOwnerId });
  });

  it("does not allow a team 'auditor' (read-only) to replay on the owner's behalf", async () => {
    const teamOwnerId = "someone-else";
    queues.scans = [{ data: { id: SCAN_ID, owner: teamOwnerId, target_url: TARGET_URL } }];
    queues.teams = [{ data: { id: "team-1" }, error: null }];
    queues.team_members = [{ data: { role: "auditor" }, error: null }];

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
    expect(inserted).toEqual([]);
  });

  it("returns 400 when the target URL now fails an SSRF check", async () => {
    queues.scans = [{ data: { id: SCAN_ID, owner: OWNER_ID, target_url: TARGET_URL } }];
    validateNoSsrfMock.mockRejectedValue(new Error("resolves to a private IP"));
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("returns 403 when domain ownership verification is no longer on file", async () => {
    queues.scans = [{ data: { id: SCAN_ID, owner: OWNER_ID, target_url: TARGET_URL } }];
    isDomainVerifiedMock.mockResolvedValue(false);
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("resolves the target's current scan_profile and dispatches on-demand for a 'safe' replay", async () => {
    queues.scans = [{ data: { id: SCAN_ID, owner: OWNER_ID, target_url: TARGET_URL } }];
    queues.monitored_targets = [{ data: { scan_profile: "safe" }, error: null }];
    queues.scans.push({ data: { id: "new-scan-1" }, error: null }); // the replay's own scans insert
    queues.scan_jobs = [{ data: null, error: null }];

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(202);
    expect(res._getJSONData()).toEqual({ ok: true, scanId: "new-scan-1", status: "queued", scanProfile: "safe" });

    const jobInsert = inserted.find((i) => i.table === "scan_jobs");
    expect(jobInsert?.payload).toEqual({
      owner: OWNER_ID,
      target_url: TARGET_URL,
      scan_id: "new-scan-1",
      scan_profile: "safe",
      status: "pending",
    });
    expect(triggerOnDemandWorkflowMock).toHaveBeenCalledTimes(1);
  });

  it("defaults to 'safe' when the target has no monitored_targets row", async () => {
    queues.scans = [{ data: { id: SCAN_ID, owner: OWNER_ID, target_url: TARGET_URL } }];
    queues.monitored_targets = [{ data: null, error: null }];
    queues.scans.push({ data: { id: "new-scan-1" }, error: null });
    queues.scan_jobs = [{ data: null, error: null }];

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getJSONData().scanProfile).toBe("safe");
    expect(triggerOnDemandWorkflowMock).toHaveBeenCalledTimes(1);
  });

  it("does NOT dispatch the on-demand workflow for a non-'safe' profile replay, leaving it for the scheduled cron", async () => {
    queues.scans = [{ data: { id: SCAN_ID, owner: OWNER_ID, target_url: TARGET_URL } }];
    queues.monitored_targets = [{ data: { scan_profile: "full" }, error: null }];
    queues.scans.push({ data: { id: "new-scan-1" }, error: null });
    queues.scan_jobs = [{ data: null, error: null }];

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(202);
    const body = res._getJSONData();
    expect(body.scanProfile).toBe("full");
    expect(body.note).toMatch(/scheduled scan runner/);
    expect(triggerOnDemandWorkflowMock).not.toHaveBeenCalled();

    const jobInsert = inserted.find((i) => i.table === "scan_jobs");
    expect(jobInsert?.payload).toMatchObject({ scan_profile: "full" });
  });

  it("marks the new scan failed and returns 500 if queuing the scan_jobs row fails", async () => {
    queues.scans = [{ data: { id: SCAN_ID, owner: OWNER_ID, target_url: TARGET_URL } }];
    queues.monitored_targets = [{ data: { scan_profile: "safe" }, error: null }];
    queues.scans.push({ data: { id: "new-scan-1" }, error: null });
    queues.scan_jobs = [{ data: null, error: { message: "db down" } }];

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(500);
    expect(triggerOnDemandWorkflowMock).not.toHaveBeenCalled();
  });

  it("returns 500 if creating the replay scan row fails", async () => {
    queues.scans = [{ data: { id: SCAN_ID, owner: OWNER_ID, target_url: TARGET_URL } }];
    queues.monitored_targets = [{ data: { scan_profile: "safe" }, error: null }];
    queues.scans.push({ data: null, error: { message: "insert failed" } });

    const { req, res } = mockReqRes();
    await handler(req, res);

    expect(res._getStatusCode()).toBe(500);
    expect(triggerOnDemandWorkflowMock).not.toHaveBeenCalled();
  });
});

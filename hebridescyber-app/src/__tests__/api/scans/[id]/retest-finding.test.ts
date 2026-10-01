import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { EXTENDED_TOOL_PREFIXES } from "@/lib/extendedToolCheckIds";

const { authenticateApiRequestMock, checkRateLimitMock, triggerOnDemandWorkflowMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  checkRateLimitMock: vi.fn(),
  triggerOnDemandWorkflowMock: vi.fn(),
}));

type QueueMap = Record<string, unknown[]>;
let queues: QueueMap = {};
const inserted: Array<{ table: string; payload: unknown }> = [];

function makeBuilder(table: string) {
  const next = () => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    order: () => builder,
    limit: () => builder,
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

import handler from "@/pages/api/scans/[id]/retest-finding";

const OWNER_ID = "owner-1";
const SCAN_ID = "scan-1";
const TARGET_URL = "https://example.com";

function mockReqRes(body: Record<string, unknown> = { checkId: "headers.missing" }) {
  return createMocks<NextApiRequest, NextApiResponse>({ method: "POST", query: { id: SCAN_ID }, body });
}

function seedFinding(checkId: string) {
  queues.scans = [{ data: { id: SCAN_ID, owner: OWNER_ID, target_url: TARGET_URL } }];
  queues.scan_results = [{ data: { results: { findings: [{ checkId, severity: "medium", title: "t", detail: "d" }] } } }];
}

describe("POST /api/scans/[id]/retest-finding", () => {
  beforeEach(() => {
    queues = {};
    inserted.length = 0;
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: OWNER_ID, via: "session" });
    checkRateLimitMock.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
    triggerOnDemandWorkflowMock.mockReset().mockResolvedValue(undefined);
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

  it("returns 429 when rate-limited, before touching scans/scan_results", async () => {
    checkRateLimitMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 33 });
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(429);
    expect(res._getHeaders()["retry-after"]).toBe("33");
    expect(inserted).toEqual([]);
    expect(triggerOnDemandWorkflowMock).not.toHaveBeenCalled();
  });

  it("returns 400 when checkId is missing", async () => {
    const { req, res } = mockReqRes({});
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
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

  it("allows a team 'admin' to retest on the owner's behalf, attributing the new scan to the owner", async () => {
    const teamOwnerId = "someone-else";
    queues.scans = [{ data: { id: SCAN_ID, owner: teamOwnerId, target_url: TARGET_URL } }];
    queues.scan_results = [{ data: { results: { findings: [{ checkId: "headers.missing", severity: "medium", title: "t", detail: "d" }] } } }];
    queues.teams = [{ data: { id: "team-1" }, error: null }];
    queues.team_members = [{ data: { role: "admin" }, error: null }];
    queues.scans.push({ data: { id: "new-scan-1" }, error: null });
    queues.scan_jobs = [{ data: null, error: null }];

    const { req, res } = mockReqRes({ checkId: "headers.missing" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(202);
    const scansInsert = inserted.find((i) => i.table === "scans");
    expect(scansInsert?.payload).toMatchObject({ owner: teamOwnerId });
  });

  it("returns 404 when there are no results for the scan yet", async () => {
    queues.scans = [{ data: { id: SCAN_ID, owner: OWNER_ID, target_url: TARGET_URL } }];
    queues.scan_results = [{ data: null }];
    const { req, res } = mockReqRes();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);
  });

  it("returns 404 when the checkId matches no finding on the scan", async () => {
    seedFinding("headers.missing");
    const { req, res } = mockReqRes({ checkId: "tls.expiring" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);
  });

  it.each(EXTENDED_TOOL_PREFIXES)(
    "rejects a %s.* finding with 400 and never queues a retest",
    async (prefix) => {
      const checkId = `${prefix}.some-check`;
      seedFinding(checkId);
      const { req, res } = mockReqRes({ checkId });

      await handler(req, res);

      expect(res._getStatusCode()).toBe(400);
      expect(JSON.parse(res._getData()).code).toBe("not_retestable");
      expect(inserted).toEqual([]);
      expect(triggerOnDemandWorkflowMock).not.toHaveBeenCalled();
    }
  );

  it("does not reject a base-suite finding sharing a word with an extended-tool prefix's namespace", async () => {
    // recon.subdomains-found (base suite) vs subdomains.* (extended Subfinder) — must not collide.
    seedFinding("recon.subdomains-found");
    queues.scans.push({ data: { id: "new-scan-1" }, error: null }); // the retest's own scans insert
    queues.scan_jobs = [{ data: null, error: null }];
    const { req, res } = mockReqRes({ checkId: "recon.subdomains-found" });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(202);
  });

  it("queues a retest and returns 202 for a valid, owned, retestable finding", async () => {
    seedFinding("headers.missing");
    queues.scans.push({ data: { id: "new-scan-1" }, error: null }); // the retest's own scans insert
    queues.scan_jobs = [{ data: null, error: null }];

    const { req, res } = mockReqRes({ checkId: "headers.missing" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(202);
    expect(res._getJSONData()).toEqual({ ok: true, scanId: "new-scan-1", status: "queued", checkId: "headers.missing" });

    const scansInsert = inserted.find((i) => i.table === "scans");
    expect(scansInsert?.payload).toEqual({
      owner: OWNER_ID,
      target_url: TARGET_URL,
      status: "running",
      owner_verified: true,
    });

    const jobInsert = inserted.find((i) => i.table === "scan_jobs");
    expect(jobInsert?.payload).toEqual({
      owner: OWNER_ID,
      target_url: TARGET_URL,
      scan_id: "new-scan-1",
      status: "pending",
    });

    expect(triggerOnDemandWorkflowMock).toHaveBeenCalledTimes(1);
  });

  it("marks the new scan failed and returns 500 if queuing the scan_jobs row fails", async () => {
    seedFinding("headers.missing");
    queues.scans.push({ data: { id: "new-scan-1" }, error: null });
    queues.scan_jobs = [{ data: null, error: { message: "db down" } }];

    const { req, res } = mockReqRes({ checkId: "headers.missing" });
    await handler(req, res);

    expect(res._getStatusCode()).toBe(500);
    expect(triggerOnDemandWorkflowMock).not.toHaveBeenCalled();
  });
});

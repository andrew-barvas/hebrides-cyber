import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import { CE_QUESTIONS } from "@/lib/ceSelfAssessment";

const { authenticateApiRequestMock, logAuditEventMock } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  logAuditEventMock: vi.fn(),
}));

type Result = { data: unknown; error: { code?: string; message: string } | null };
let selectResult: Result;
let upsertResult: Result;
let upserted: { rows: Record<string, unknown>[]; options: unknown } | null;

function builder() {
  const b: Record<string, unknown> = {
    select: () => b,
    eq: () => b,
    upsert: (rows: Record<string, unknown>[], options: unknown) => {
      upserted = { rows, options };
      return Promise.resolve(upsertResult);
    },
    // GET: `select(...).eq(...)` is awaited directly.
    then: (resolve: (v: unknown) => unknown) => Promise.resolve(selectResult).then(resolve),
  };
  return b;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: () => builder() },
}));
vi.mock("@/lib/audit", () => ({ logAuditEvent: logAuditEventMock }));

import handler from "@/pages/api/account/ce-assessment";

function call(method: RequestMethod, body?: Record<string, unknown>) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, body });
  return handler(req, res).then(() => res);
}

const firstKey = CE_QUESTIONS[0].key;
const secondKey = CE_QUESTIONS[1].key;

describe("/api/account/ce-assessment", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "o1", via: "session" });
    logAuditEventMock.mockReset();
    upserted = null;
    selectResult = { data: [], error: null };
    upsertResult = { data: null, error: null };
  });

  it("requires authentication", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    expect((await call("GET"))._getStatusCode()).toBe(401);
  });

  it("rejects other methods", async () => {
    expect((await call("DELETE"))._getStatusCode()).toBe(405);
  });

  it("returns the owner's saved answers", async () => {
    selectResult = {
      data: [{ control: CE_QUESTIONS[0].control, question_key: firstKey, answer: "yes", note: null, updated_at: "t" }],
      error: null,
    };
    const res = await call("GET");
    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toMatchObject({ available: true, answers: [{ questionKey: firstKey, answer: "yes" }] });
  });

  it("reports available:false before migration 061 on GET", async () => {
    selectResult = { data: null, error: { code: "PGRST205", message: "Could not find the table" } };
    const res = await call("GET");
    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toMatchObject({ available: false, answers: [] });
  });

  it("upserts answers, maps each to its control, and audits", async () => {
    const res = await call("PUT", { answers: [{ questionKey: firstKey, answer: "yes" }, { questionKey: secondKey, answer: "no", note: "n" }] });
    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toMatchObject({ saved: 2 });
    expect(upserted?.options).toEqual({ onConflict: "owner,question_key" });
    expect(upserted?.rows).toHaveLength(2);
    expect(upserted?.rows[0]).toMatchObject({ owner: "o1", question_key: firstKey, answer: "yes", control: CE_QUESTIONS[0].control });
    expect(logAuditEventMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "ce_assessment.saved" }));
  });

  it("de-dupes repeated keys (last wins)", async () => {
    await call("PUT", { answers: [{ questionKey: firstKey, answer: "yes" }, { questionKey: firstKey, answer: "no" }] });
    expect(upserted?.rows).toHaveLength(1);
    expect(upserted?.rows[0]).toMatchObject({ question_key: firstKey, answer: "no" });
  });

  it("rejects an unknown question key", async () => {
    const res = await call("PUT", { answers: [{ questionKey: "not.a.real.key", answer: "yes" }] });
    expect(res._getStatusCode()).toBe(400);
    expect(upserted).toBeNull();
  });

  it("rejects an invalid answer value", async () => {
    const res = await call("PUT", { answers: [{ questionKey: firstKey, answer: "maybe" }] });
    expect(res._getStatusCode()).toBe(400);
    expect(upserted).toBeNull();
  });

  it("returns 503 when saving before migration 061", async () => {
    upsertResult = { data: null, error: { code: "PGRST205", message: "Could not find the table" } };
    const res = await call("PUT", { answers: [{ questionKey: firstKey, answer: "yes" }] });
    expect(res._getStatusCode()).toBe(503);
  });

  it("accepts an empty answer set without touching the table, and still audits", async () => {
    const res = await call("PUT", { answers: [] });
    expect(res._getStatusCode()).toBe(200);
    expect(upserted).toBeNull();
    expect(logAuditEventMock).toHaveBeenCalled();
  });
});

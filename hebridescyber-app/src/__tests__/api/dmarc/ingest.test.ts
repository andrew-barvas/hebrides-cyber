import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import { gzipSync } from "node:zlib";
import { Readable } from "node:stream";
import type { NextApiRequest, NextApiResponse } from "next";

const { rateLimit, resolveToken, parseReport, upsert } = vi.hoisted(() => ({
  rateLimit: vi.fn(),
  resolveToken: vi.fn(),
  parseReport: vi.fn(),
  upsert: vi.fn(),
}));

vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: rateLimit, getClientIp: () => "1.2.3.4" }));
vi.mock("@/lib/supabaseAdmin", () => ({ supabaseAdmin: { from: () => ({ upsert }) } }));
vi.mock("@/lib/dmarcReports", () => ({
  resolveIngestToken: resolveToken,
  toReportInsert: (owner: string) => ({ owner, domain: "example.com", org_name: "google.com", total_messages: 10, passing_messages: 9, failing_messages: 1 }),
}));
vi.mock("@/lib/dmarcAggregate", () => ({ parseDmarcAggregateReport: parseReport }));

import handler from "@/pages/api/dmarc/ingest";

// The handler reads the raw stream (bodyParser is off), so feed it as one.
function call(opts: { method?: string; body?: Buffer; query?: Record<string, string>; headers?: Record<string, string> }) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: (opts.method ?? "POST") as "POST", query: opts.query, headers: opts.headers });
  const stream = Readable.from([opts.body ?? Buffer.from("<feedback/>")]);
  Object.assign(req, { [Symbol.asyncIterator]: stream[Symbol.asyncIterator].bind(stream), on: stream.on.bind(stream), pipe: stream.pipe.bind(stream) });
  return handler(req, res).then(() => res);
}

beforeEach(() => {
  rateLimit.mockReset().mockResolvedValue({ allowed: true });
  resolveToken.mockReset().mockResolvedValue("owner-1");
  parseReport.mockReset().mockReturnValue({ ok: true });
  upsert.mockReset().mockResolvedValue({ error: null });
});

describe("POST /api/dmarc/ingest", () => {
  it("rejects non-POST", async () => {
    expect((await call({ method: "GET" })).statusCode).toBe(405);
  });

  it("rate-limits before looking at the token", async () => {
    rateLimit.mockResolvedValue({ allowed: false });
    const res = await call({ query: { token: "t" } });
    expect(res.statusCode).toBe(429);
    expect(resolveToken).not.toHaveBeenCalled();
  });

  it("401s without a valid ingest token and never stores anything", async () => {
    resolveToken.mockResolvedValue(null);
    const res = await call({});
    expect(res.statusCode).toBe(401);
    expect(upsert).not.toHaveBeenCalled();
  });

  it("accepts the token from the query string or a Bearer header", async () => {
    await call({ query: { token: "from-query" } });
    expect(resolveToken).toHaveBeenLastCalledWith(expect.anything(), "from-query");
    await call({ headers: { authorization: "Bearer from-header" } });
    expect(resolveToken).toHaveBeenLastCalledWith(expect.anything(), "from-header");
  });

  it("gunzips a gzip body before parsing", async () => {
    await call({ query: { token: "t" }, body: gzipSync("<feedback>zipped</feedback>") });
    expect(parseReport).toHaveBeenCalledWith("<feedback>zipped</feedback>");
  });

  it("400s on a body that isn't a DMARC report", async () => {
    parseReport.mockReturnValue(null);
    const res = await call({ query: { token: "t" } });
    expect(res.statusCode).toBe(400);
    expect(upsert).not.toHaveBeenCalled();
  });

  it("400s on a corrupt gzip body", async () => {
    const res = await call({ query: { token: "t" }, body: Buffer.from([0x1f, 0x8b, 0x00, 0x01]) });
    expect(res.statusCode).toBe(400);
  });

  it("stores idempotently on owner+domain+report_id and answers 202", async () => {
    const res = await call({ query: { token: "t" } });
    expect(res.statusCode).toBe(202);
    expect(upsert).toHaveBeenCalledWith(expect.objectContaining({ owner: "owner-1" }), { onConflict: "owner,domain,report_id" });
    expect(res._getJSONData()).toMatchObject({ accepted: true, total: 10, failing: 1 });
  });

  it("503s while migration 060 is pending, 500s on any other write error", async () => {
    upsert.mockResolvedValue({ error: { code: "42P01", message: 'relation "dmarc_reports" does not exist' } });
    expect((await call({ query: { token: "t" } })).statusCode).toBe(503);
    upsert.mockResolvedValue({ error: { code: "XX000", message: "boom" } });
    expect((await call({ query: { token: "t" } })).statusCode).toBe(500);
  });
});

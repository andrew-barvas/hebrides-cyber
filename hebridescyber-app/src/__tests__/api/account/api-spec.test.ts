import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const m = vi.hoisted(() => ({
  auth: vi.fn(),
  ssrf: vi.fn(),
  existing: { data: null as unknown },
  list: { data: [] as unknown[], error: null as unknown },
  write: { error: null as unknown },
  inserts: [] as unknown[],
  updates: [] as unknown[],
  deletes: 0,
  eqCalls: [] as string[],
}));

vi.mock("@/lib/ownership", () => ({ validateNoSsrf: m.ssrf }));
vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: m.auth,
  supabaseAdmin: {
    from: () => {
      const b: Record<string, unknown> = {};
      let op = "select";
      for (const name of ["select", "order"]) b[name] = () => b;
      b.eq = (col: string, val: unknown) => {
        m.eqCalls.push(`${col}=${String(val)}`);
        return b;
      };
      b.insert = (row: unknown) => {
        op = "write";
        m.inserts.push(row);
        return b;
      };
      b.update = (row: unknown) => {
        op = "write";
        m.updates.push(row);
        return b;
      };
      b.delete = () => {
        op = "write";
        m.deletes++;
        return b;
      };
      b.maybeSingle = () => Promise.resolve(m.existing);
      b.then = (resolve: (v: unknown) => void) => resolve(op === "write" ? m.write : m.list);
      return b;
    },
  },
}));

import handler from "@/pages/api/account/api-spec";

const TARGET = "https://api.example.com";
const SPEC = { openapi: "3.0.1", paths: { "/users": {}, "/orders": {} } };
const UUID = "7d0c5d0e-1b7e-4a3c-9d57-0f6f3f5a1c11";

function call(method: string, body?: unknown) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "GET", body: body as Record<string, unknown> });
  return handler(req, res).then(() => res as Omit<typeof res, "_getJSONData"> & { _getJSONData(): any }); // eslint-disable-line @typescript-eslint/no-explicit-any
}

const fetchMock = vi.fn();

beforeEach(() => {
  m.auth.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
  m.ssrf.mockReset().mockResolvedValue("ok");
  m.existing = { data: null };
  m.list = { data: [], error: null };
  m.write = { error: null };
  m.inserts.length = 0;
  m.updates.length = 0;
  m.deletes = 0;
  m.eqCalls.length = 0;
  fetchMock.mockReset().mockResolvedValue(new Response(JSON.stringify(SPEC)));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("/api/account/api-spec", () => {
  it("405s unsupported methods before authenticating", async () => {
    expect((await call("PUT")).statusCode).toBe(405);
    expect(m.auth).not.toHaveBeenCalled();
  });

  it("401s when unauthenticated", async () => {
    m.auth.mockResolvedValue(null);
    expect((await call("GET")).statusCode).toBe(401);
  });

  describe("GET", () => {
    it("returns a summary with the endpoint count, never the spec body", async () => {
      m.list = { data: [{ id: "a", target_url: TARGET, spec_format: "openapi3", source_url: null, created_at: "c", updated_at: "u", spec_content: SPEC }], error: null };
      const res = await call("GET");
      const [spec] = res._getJSONData().specs;
      expect(spec).toMatchObject({ id: "a", endpoint_count: 2 });
      expect(spec).not.toHaveProperty("spec_content");
      expect(m.eqCalls).toContain("owner=owner-1");
    });

    it("counts zero endpoints for a malformed stored spec", async () => {
      m.list = { data: [{ id: "a", spec_content: { paths: [] } }, { id: "b", spec_content: null }], error: null };
      const specs = (await call("GET"))._getJSONData().specs;
      expect(specs.map((s: { endpoint_count: number }) => s.endpoint_count)).toEqual([0, 0]);
    });

    it("500s on a database error", async () => {
      m.list = { data: [], error: { message: "db" } };
      expect((await call("GET")).statusCode).toBe(500);
    });
  });

  describe("DELETE", () => {
    it("needs a uuid and deletes only the caller's row", async () => {
      expect((await call("DELETE", { id: "nope" })).statusCode).toBe(400);
      const res = await call("DELETE", { id: UUID });
      expect(res.statusCode).toBe(200);
      expect(m.eqCalls).toEqual(expect.arrayContaining([`id=${UUID}`, "owner=owner-1"]));
    });
  });

  describe("POST with spec_content", () => {
    it.each([
      [{ openapi: "3.0.0", paths: { "/a": {} } }, "openapi3"],
      [{ swagger: "2.0", paths: { "/a": {} } }, "openapi2"],
      [{ openapi: "4.0", paths: { "/a": {} } }, "swagger"],
    ])("detects the format of %j as %s", async (spec, format) => {
      const res = await call("POST", { target_url: TARGET, spec_content: spec });
      expect(res.statusCode).toBe(200);
      expect(res._getJSONData()).toMatchObject({ ok: true, spec_format: format, endpoint_count: 1 });
    });

    it.each([
      ["no paths", { openapi: "3.0.0" }],
      ["empty paths", { openapi: "3.0.0", paths: {} }],
      ["array paths", { openapi: "3.0.0", paths: [] }],
      ["no version key", { paths: { "/a": {} } }],
    ])("rejects a spec with %s", async (_n, spec) => {
      const res = await call("POST", { target_url: TARGET, spec_content: spec });
      expect(res.statusCode).toBe(400);
      expect(m.inserts).toEqual([]);
    });

    it("400s on an empty spec_content or a bad target_url", async () => {
      expect((await call("POST", { target_url: TARGET, spec_content: {} })).statusCode).toBe(400);
      expect((await call("POST", { target_url: "nope", spec_content: SPEC })).statusCode).toBe(400);
    });

    it("inserts a new spec for a new target, and replaces rather than duplicates for a known one", async () => {
      await call("POST", { target_url: TARGET, spec_content: SPEC });
      expect(m.inserts[0]).toMatchObject({ owner: "owner-1", target_url: TARGET, source_url: null });
      m.existing = { data: { id: "existing-1" } };
      await call("POST", { target_url: TARGET, spec_content: SPEC });
      expect(m.updates).toHaveLength(1);
      expect(m.inserts).toHaveLength(1);
    });

    it("500s when the write fails", async () => {
      m.write = { error: { message: "boom" } };
      expect((await call("POST", { target_url: TARGET, spec_content: SPEC })).statusCode).toBe(500);
    });
  });

  describe("POST with spec_url", () => {
    const body = { target_url: TARGET, spec_url: "https://api.example.com/openapi.json" };

    it("fetches the spec, records its source, and stores it", async () => {
      const res = await call("POST", body);
      expect(res.statusCode).toBe(200);
      expect(m.inserts[0]).toMatchObject({ source_url: body.spec_url });
    });

    it("refuses an internal spec_url without fetching it (SSRF)", async () => {
      m.ssrf.mockRejectedValue(new Error("Target IP 169.254.169.254 is in a restricted private range"));
      const res = await call("POST", { ...body, spec_url: "http://169.254.169.254/latest/meta-data" });
      expect(res.statusCode).toBe(400);
      expect(res._getJSONData().error).toContain("restricted private range");
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("does not follow redirects — a public URL can't bounce the server inward", async () => {
      fetchMock.mockResolvedValue(new Response(null, { status: 302, headers: { location: "http://169.254.169.254/" } }));
      const res = await call("POST", body);
      expect(res.statusCode).toBe(400);
      expect(fetchMock).toHaveBeenCalledWith(body.spec_url, expect.objectContaining({ redirect: "manual" }));
      expect(m.inserts).toEqual([]);
    });

    it("400s on an HTTP error, a non-JSON body, an oversized body, and a network failure", async () => {
      fetchMock.mockResolvedValue(new Response("nope", { status: 404 }));
      expect((await call("POST", body)).statusCode).toBe(400);
      fetchMock.mockResolvedValue(new Response("openapi: 3.0.0"));
      expect((await call("POST", body)).statusCode).toBe(400);
      fetchMock.mockResolvedValue(new Response("x".repeat(5 * 1024 * 1024 + 1)));
      expect((await call("POST", body)).statusCode).toBe(400);
      fetchMock.mockRejectedValue(new Error("timeout"));
      expect((await call("POST", body)).statusCode).toBe(400);
      expect(m.inserts).toEqual([]);
    });
  });
});

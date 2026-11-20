import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

type Reply = { data?: unknown; error?: unknown };
const { rateMock, auditMock, sendEmailMock, getMock, profileMock, queues, writes, eqs } = vi.hoisted(() => ({
  rateMock: vi.fn(),
  auditMock: vi.fn(),
  sendEmailMock: vi.fn(),
  getMock: vi.fn(),
  profileMock: vi.fn(),
  queues: {} as Record<string, Reply[]>,
  writes: [] as Array<{ table: string; op: string; row: unknown }>,
  eqs: [] as Array<[string, string, unknown]>,
}));

function builder(table: string) {
  const next = (): Promise<Reply> => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const q: Record<string, unknown> = {};
  for (const m of ["select", "in", "is", "order", "limit"]) q[m] = () => q;
  q.eq = (c: string, v: unknown) => {
    eqs.push([table, c, v]);
    return q;
  };
  for (const op of ["insert", "update"]) {
    q[op] = (row: unknown) => {
      writes.push({ table, op, row });
      return q;
    };
  }
  q.maybeSingle = next;
  q.then = (r: (v: unknown) => void, j: (e: unknown) => void) => next().then(r, j);
  return q;
}

vi.mock("@/lib/supabaseAdmin", () => ({ supabaseAdmin: { from: (t: string) => builder(t) } }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: rateMock, getClientIp: () => "203.0.113.9" }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: auditMock }));
vi.mock("@/lib/email", async (orig) => ({ ...(await orig<typeof import("@/lib/email")>()), sendEmail: sendEmailMock }));
vi.mock("@/lib/objectStore", () => ({ supabaseObjectStore: () => ({ get: getMock, put: vi.fn() }) }));
vi.mock("@/lib/securityProfile", async (orig) => ({ ...(await orig<typeof import("@/lib/securityProfile")>()), loadProfileBySlug: profileMock }));

import download from "@/pages/api/profile/[slug]/documents/[id]";
import requestAccess from "@/pages/api/profile/[slug]/documents/[id]/request";
import tokenDownload from "@/pages/api/trust-download";
import { hashDownloadToken } from "@/lib/trustDocuments";

const DOC = "11111111-1111-4111-8111-111111111111";
const doc = (visibility: "public" | "on_request") => ({ id: DOC, owner: "o1", target_host: "shop.example.com", title: "CE 2026", kind: "cyber_essentials", visibility, object_key: "o1/shop.example.com/x.pdf", size_bytes: 9, uploaded_at: "2026-11-01T00:00:00Z", deleted_at: null });
const BYTES = Buffer.from("%PDF-1.7\n");
const TOKEN = "B".repeat(43);

async function call(handler: (req: NextApiRequest, res: NextApiResponse) => unknown, method: string, query: Record<string, string>, body?: unknown) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "GET", query, body: body as never });
  await handler(req, res);
  return res;
}

beforeEach(() => {
  rateMock.mockReset().mockResolvedValue({ allowed: true });
  auditMock.mockReset();
  sendEmailMock.mockReset().mockResolvedValue({ ok: true });
  getMock.mockReset().mockResolvedValue(BYTES);
  profileMock.mockReset().mockResolvedValue({ owner: "o1", target_host: "shop.example.com", slug: "abcdefghijkl" });
  for (const k of Object.keys(queues)) delete queues[k];
  writes.length = 0;
  eqs.length = 0;
});

describe("GET /api/profile/[slug]/documents/[id]", () => {
  it("serves a public document as a non-sniffable attachment", async () => {
    queues.trust_documents = [{ data: doc("public") }];
    const res = await call(download, "GET", { slug: "abcdefghijkl", id: DOC });
    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Content-Disposition")).toBe('attachment; filename="CE-2026.pdf"');
    expect(res.getHeader("X-Content-Type-Options")).toBe("nosniff");
    expect(eqs).toContainEqual(["trust_documents", "owner", "o1"]);
  });

  it("never serves an on-request document, and answers one 404 for every unavailable case", async () => {
    queues.trust_documents = [{ data: doc("on_request") }];
    const onRequest = await call(download, "GET", { slug: "abcdefghijkl", id: DOC });
    expect(onRequest._getStatusCode()).toBe(404);
    profileMock.mockResolvedValueOnce(null);
    const noProfile = await call(download, "GET", { slug: "nope", id: DOC });
    expect(noProfile._getJSONData()).toEqual(onRequest._getJSONData());
    queues.trust_documents = [{ data: null }];
    expect((await call(download, "GET", { slug: "abcdefghijkl", id: DOC }))._getJSONData()).toEqual(onRequest._getJSONData());
    expect(getMock).not.toHaveBeenCalled();
  });

  it("is rate-limited per IP", async () => {
    rateMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 60 });
    expect((await call(download, "GET", { slug: "abcdefghijkl", id: DOC }))._getStatusCode()).toBe(429);
  });
});

describe("POST /api/profile/[slug]/documents/[id]/request", () => {
  const body = { name: "Sam <b>", email: "Sam@Insurer.example", company: "Acme", reason: "Renewal" };

  it("records the request, emails the owner (escaped), and releases nothing", async () => {
    queues.trust_documents = [{ data: doc("on_request") }];
    queues.trust_document_requests = [{ data: [] }, { data: null, error: null }];
    queues.users = [{ data: { email: "owner@example.com" } }];
    const res = await call(requestAccess, "POST", { slug: "abcdefghijkl", id: DOC }, body);
    expect(res._getStatusCode()).toBe(200);
    expect(writes.find((w) => w.op === "insert")?.row).toMatchObject({ document_id: DOC, requester_email: "sam@insurer.example", requester_company: "Acme" });
    expect(sendEmailMock.mock.calls[0][0].to).toBe("owner@example.com");
    expect(sendEmailMock.mock.calls[0][0].html).toContain("Sam &lt;b&gt;");
    expect(getMock).not.toHaveBeenCalled();
  });

  it("answers the same for a repeat or over-cap request, without writing or emailing again", async () => {
    queues.trust_documents = [{ data: doc("on_request") }];
    queues.trust_document_requests = [{ data: [{ requester_email: "sam@insurer.example" }] }];
    const repeat = await call(requestAccess, "POST", { slug: "abcdefghijkl", id: DOC }, body);
    expect(repeat._getStatusCode()).toBe(200);
    expect(writes).toEqual([]);
    expect(sendEmailMock).not.toHaveBeenCalled();
  });

  it("won't take requests for public documents", async () => {
    queues.trust_documents = [{ data: doc("public") }];
    expect((await call(requestAccess, "POST", { slug: "abcdefghijkl", id: DOC }, body))._getStatusCode()).toBe(404);
  });
});

describe("GET /api/trust-download", () => {
  const approved = { id: "r1", document_id: DOC, status: "approved", expires_at: "2099-01-01T00:00:00Z", download_count: 1 };

  it("looks the link up by hash, counts the download, audits it and serves the file", async () => {
    queues.trust_document_requests = [{ data: approved }, { data: [{ id: "r1" }] }];
    queues.trust_documents = [{ data: { id: DOC, owner: "o1", title: "CE 2026", object_key: "k" } }];
    const res = await call(tokenDownload, "GET", { token: TOKEN });
    expect(res._getStatusCode()).toBe(200);
    expect(eqs).toContainEqual(["trust_document_requests", "token_hash", hashDownloadToken(TOKEN)]);
    expect(eqs.some(([, , v]) => v === TOKEN)).toBe(false);
    expect(writes.find((w) => w.op === "update")?.row).toEqual({ download_count: 2 });
    expect(auditMock.mock.calls[0][1]).toMatchObject({ actorId: "o1", action: "trust_document.downloaded" });
  });

  it("refuses expired, used-up and malformed links, and a deleted document", async () => {
    queues.trust_document_requests = [{ data: { ...approved, expires_at: "2020-01-01T00:00:00Z" } }];
    expect((await call(tokenDownload, "GET", { token: TOKEN }))._getStatusCode()).toBe(404);
    queues.trust_document_requests = [{ data: { ...approved, download_count: 5 } }];
    expect((await call(tokenDownload, "GET", { token: TOKEN }))._getStatusCode()).toBe(404);
    expect((await call(tokenDownload, "GET", { token: "short" }))._getStatusCode()).toBe(404);
    queues.trust_document_requests = [{ data: approved }];
    queues.trust_documents = [{ data: null }];
    expect((await call(tokenDownload, "GET", { token: TOKEN }))._getStatusCode()).toBe(404);
    expect(getMock).not.toHaveBeenCalled();
  });

  it("won't let two downloads share the last allowance", async () => {
    queues.trust_document_requests = [{ data: approved }, { data: [] }];
    queues.trust_documents = [{ data: { id: DOC, owner: "o1", title: "CE 2026", object_key: "k" } }];
    const res = await call(tokenDownload, "GET", { token: TOKEN });
    expect(res._getStatusCode()).toBe(404);
    expect(auditMock).not.toHaveBeenCalled();
  });
});

describe("public document routes: methods, limits and failures", () => {
  it("refuses other methods on every public route", async () => {
    expect((await call(download, "POST", { slug: "abcdefghijkl", id: DOC }))._getStatusCode()).toBe(405);
    expect((await call(requestAccess, "GET", { slug: "abcdefghijkl", id: DOC }))._getStatusCode()).toBe(405);
    expect((await call(tokenDownload, "POST", { token: TOKEN }))._getStatusCode()).toBe(405);
  });

  it("rate-limits requests and token downloads per IP", async () => {
    rateMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 60 });
    expect((await call(requestAccess, "POST", { slug: "abcdefghijkl", id: DOC }, { name: "Sam", email: "sam@x.example" }))._getStatusCode()).toBe(429);
    expect((await call(tokenDownload, "GET", { token: TOKEN }))._getStatusCode()).toBe(429);
  });

  it("refuses a malformed request, and 404s a request for a document on a missing profile", async () => {
    expect((await call(requestAccess, "POST", { slug: "abcdefghijkl", id: DOC }, { name: "", email: "not-an-email" }))._getStatusCode()).toBe(400);
    profileMock.mockResolvedValueOnce(null);
    expect((await call(requestAccess, "POST", { slug: "nope", id: DOC }, { name: "Sam", email: "sam@x.example" }))._getStatusCode()).toBe(404);
  });

  it("answers 500 when a document can't be read, and 404 when its file is gone", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    queues.trust_documents = [{ error: { message: "db down" } }];
    expect((await call(download, "GET", { slug: "abcdefghijkl", id: DOC }))._getStatusCode()).toBe(500);
    queues.trust_documents = [{ error: { message: "db down" } }];
    expect((await call(requestAccess, "POST", { slug: "abcdefghijkl", id: DOC }, { name: "Sam", email: "sam@x.example" }))._getStatusCode()).toBe(500);
    queues.trust_documents = [{ data: doc("public") }];
    getMock.mockResolvedValueOnce(null);
    expect((await call(download, "GET", { slug: "abcdefghijkl", id: DOC }))._getStatusCode()).toBe(404);
    queues.trust_documents = [{ data: doc("public") }];
    getMock.mockRejectedValueOnce(new Error("storage down"));
    expect((await call(download, "GET", { slug: "abcdefghijkl", id: DOC }))._getStatusCode()).toBe(500);
    spy.mockRestore();
  });

  it("refuses a token download whose file is gone or can't be fetched, and answers 500 on a lookup error", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const approved = { id: "r1", document_id: DOC, status: "approved", expires_at: "2099-01-01T00:00:00Z", download_count: 0 };
    queues.trust_document_requests = [{ data: approved }];
    queues.trust_documents = [{ data: { id: DOC, owner: "o1", title: "CE", object_key: "k" } }];
    getMock.mockResolvedValueOnce(null);
    expect((await call(tokenDownload, "GET", { token: TOKEN }))._getStatusCode()).toBe(404);
    queues.trust_document_requests = [{ data: approved }];
    queues.trust_documents = [{ data: { id: DOC, owner: "o1", title: "CE", object_key: "k" } }];
    getMock.mockRejectedValueOnce(new Error("storage down"));
    expect((await call(tokenDownload, "GET", { token: TOKEN }))._getStatusCode()).toBe(500);
    queues.trust_document_requests = [{ error: { message: "db down" } }];
    expect((await call(tokenDownload, "GET", { token: TOKEN }))._getStatusCode()).toBe(500);
    spy.mockRestore();
  });

  it("still records a request when emailing the owner fails, and caps pending requests", async () => {
    queues.trust_documents = [{ data: doc("on_request") }];
    queues.trust_document_requests = [{ data: [] }, { data: null, error: null }];
    queues.users = [{ data: { email: "owner@example.com" } }];
    sendEmailMock.mockRejectedValueOnce(new Error("mail down"));
    expect((await call(requestAccess, "POST", { slug: "abcdefghijkl", id: DOC }, { name: "Sam", email: "sam@x.example" }))._getStatusCode()).toBe(200);
    expect(writes.some((w) => w.op === "insert")).toBe(true);
    writes.length = 0;
    queues.trust_documents = [{ data: doc("on_request") }];
    queues.trust_document_requests = [{ data: Array.from({ length: 25 }, (_, i) => ({ requester_email: `p${i}@x.example` })) }];
    expect((await call(requestAccess, "POST", { slug: "abcdefghijkl", id: DOC }, { name: "Sam", email: "new@x.example" }))._getStatusCode()).toBe(200);
    expect(writes).toEqual([]);
  });
});

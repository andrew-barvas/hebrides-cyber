import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

type Reply = { data?: unknown; error?: unknown };
const { authMock, gateMock, verifiedMock, auditMock, sendEmailMock, putMock, removeMock, queues, writes } = vi.hoisted(() => ({
  authMock: vi.fn(),
  gateMock: vi.fn(),
  verifiedMock: vi.fn(),
  auditMock: vi.fn(),
  sendEmailMock: vi.fn(),
  putMock: vi.fn(),
  removeMock: vi.fn(),
  queues: {} as Record<string, Reply[]>,
  writes: [] as Array<{ table: string; op: string; row: unknown }>,
}));

function builder(table: string) {
  const next = (): Promise<Reply> => Promise.resolve(queues[table]?.shift() ?? { data: null, error: null });
  const q: Record<string, unknown> = {};
  for (const m of ["select", "eq", "in", "is", "order", "limit"]) q[m] = () => q;
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

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authMock,
  supabaseAdmin: { from: (t: string) => builder(t), storage: { from: () => ({ remove: removeMock }) } },
}));
vi.mock("@/lib/planAccess", () => ({ planGate: gateMock }));
vi.mock("@/lib/ownership", () => ({ isDomainVerified: verifiedMock }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: auditMock }));
vi.mock("@/lib/email", async (orig) => ({ ...(await orig<typeof import("@/lib/email")>()), sendEmail: sendEmailMock }));
vi.mock("@/lib/objectStore", () => ({ supabaseObjectStore: () => ({ put: putMock, get: vi.fn() }) }));

import listUpload from "@/pages/api/trust-documents/index";
import editDelete from "@/pages/api/trust-documents/[id]";
import decide from "@/pages/api/trust-documents/requests/[id]";

const DOC = "11111111-1111-4111-8111-111111111111";
const REQ = "22222222-2222-4222-8222-222222222222";
const PDF = `data:application/pdf;base64,${Buffer.from("%PDF-1.7\n%x\n").toString("base64")}`;

async function call(handler: (req: NextApiRequest, res: NextApiResponse) => unknown, method: string, opts: { body?: unknown; query?: Record<string, string> } = {}) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: method as "GET", body: opts.body as never, query: opts.query, headers: { authorization: "Bearer t" } });
  await handler(req, res);
  return res;
}

beforeEach(() => {
  authMock.mockReset().mockResolvedValue({ ownerId: "o1", via: "session" });
  gateMock.mockReset().mockResolvedValue("ok");
  verifiedMock.mockReset().mockResolvedValue(true);
  auditMock.mockReset();
  sendEmailMock.mockReset().mockResolvedValue({ ok: true });
  putMock.mockReset().mockResolvedValue(undefined);
  removeMock.mockReset().mockResolvedValue({ error: null });
  for (const k of Object.keys(queues)) delete queues[k];
  writes.length = 0;
});

describe("/api/trust-documents (upload and list)", () => {
  const upload = (extra: Record<string, unknown> = {}) => call(listUpload, "POST", { body: { targetUrl: "https://shop.example.com", title: "CE 2026", kind: "cyber_essentials", visibility: "on_request", dataUrl: PDF, ...extra } });

  it("is session-only, Pro and up, and needs a verified domain", async () => {
    authMock.mockResolvedValueOnce({ ownerId: "o1", via: "api_key" });
    expect((await upload())._getStatusCode()).toBe(403);
    gateMock.mockResolvedValueOnce("denied");
    expect((await upload())._getStatusCode()).toBe(403);
    verifiedMock.mockResolvedValueOnce(false);
    expect((await upload())._getStatusCode()).toBe(403);
    expect(putMock).not.toHaveBeenCalled();
  });

  it("refuses a file that isn't a PDF, and a full profile", async () => {
    expect((await upload({ dataUrl: `data:application/pdf;base64,${Buffer.from("<html>").toString("base64")}` }))._getStatusCode()).toBe(400);
    queues.trust_documents = [{ data: Array.from({ length: 10 }, (_, i) => ({ id: `d${i}` })) }];
    expect((await upload())._getStatusCode()).toBe(409);
    expect(putMock).not.toHaveBeenCalled();
  });

  it("stores the PDF privately under the owner and site, records it and audits it", async () => {
    queues.trust_documents = [{ data: [] }, { data: null, error: null }];
    const res = await upload();
    expect(res._getStatusCode()).toBe(201);
    expect(putMock.mock.calls[0][0]).toMatch(/^o1\/shop\.example\.com\/[0-9a-f-]{36}\.pdf$/);
    expect(putMock.mock.calls[0][2]).toBe("application/pdf");
    const row = writes.find((w) => w.table === "trust_documents" && w.op === "insert")?.row as Record<string, unknown>;
    expect(row).toMatchObject({ owner: "o1", target_host: "shop.example.com", kind: "cyber_essentials", visibility: "on_request" });
    expect(row.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect((res._getJSONData() as { document: Record<string, unknown> }).document).not.toHaveProperty("object_key");
    expect(auditMock.mock.calls[0][1]).toMatchObject({ action: "trust_document.uploaded" });
  });

  it("lists documents and their requests for the owner's site", async () => {
    queues.trust_documents = [{ data: [{ id: DOC, owner: "o1", target_host: "shop.example.com", title: "CE", kind: "cyber_essentials", visibility: "on_request", object_key: "k", size_bytes: 10, uploaded_at: "2026-11-01T00:00:00Z", deleted_at: null }] }];
    queues.trust_document_requests = [{ data: [{ id: REQ, document_id: DOC, status: "pending" }] }];
    const res = await call(listUpload, "GET", { query: { targetUrl: "https://shop.example.com" } });
    expect(res._getStatusCode()).toBe(200);
    const body = res._getJSONData() as { documents: unknown[]; requests: unknown[] };
    expect(body.documents).toHaveLength(1);
    expect(body.requests).toHaveLength(1);
  });
});

describe("/api/trust-documents/[id]", () => {
  it("404s someone else's document", async () => {
    queues.trust_documents = [{ data: null }];
    expect((await call(editDelete, "DELETE", { query: { id: DOC } }))._getStatusCode()).toBe(404);
  });

  it("changes visibility, and on delete expires outstanding links and removes the file", async () => {
    queues.trust_documents = [{ data: { id: DOC, object_key: "o1/a/x.pdf" } }];
    expect((await call(editDelete, "PATCH", { query: { id: DOC }, body: { visibility: "public" } }))._getStatusCode()).toBe(200);
    queues.trust_documents = [{ data: { id: DOC, object_key: "o1/a/x.pdf" } }];
    const res = await call(editDelete, "DELETE", { query: { id: DOC } });
    expect(res._getStatusCode()).toBe(200);
    expect(writes.some((w) => w.table === "trust_document_requests" && w.op === "update" && (w.row as Record<string, unknown>).expires_at)).toBe(true);
    expect(removeMock).toHaveBeenCalledWith(["o1/a/x.pdf"]);
    expect(auditMock.mock.calls.map((c) => c[1].action)).toEqual(["trust_document.updated", "trust_document.deleted"]);
  });
});

describe("/api/trust-documents/requests/[id]", () => {
  const pending = { id: REQ, document_id: DOC, requester_name: "Sam", requester_email: "sam@insurer.example", status: "pending" };
  const doc = { id: DOC, owner: "o1", title: "CE <2026>", target_host: "shop.example.com" };

  it("approves: stores only a token hash and emails the requester a working link", async () => {
    queues.trust_document_requests = [{ data: pending }, { data: null, error: null }];
    queues.trust_documents = [{ data: doc }];
    const res = await call(decide, "POST", { query: { id: REQ }, body: { decision: "approve" } });
    expect(res._getStatusCode()).toBe(200);
    const update = writes.find((w) => w.op === "update")?.row as Record<string, string>;
    expect(update.status).toBe("approved");
    expect(update.token_hash).toMatch(/^[0-9a-f]{64}$/);
    const html = sendEmailMock.mock.calls[0][0].html as string;
    const token = /token=([A-Za-z0-9_-]{43})/.exec(html)?.[1];
    expect(token).toBeTruthy();
    expect(html).not.toContain(update.token_hash);
    expect(html).toContain("CE &lt;2026&gt;");
    expect(sendEmailMock.mock.calls[0][0].to).toBe("sam@insurer.example");
  });

  it("declines with a neutral note; refuses decided and other owners' requests", async () => {
    queues.trust_document_requests = [{ data: pending }, { data: null }];
    queues.trust_documents = [{ data: doc }];
    expect(((await call(decide, "POST", { query: { id: REQ }, body: { decision: "decline" } }))._getJSONData() as { status: string }).status).toBe("declined");
    queues.trust_document_requests = [{ data: { ...pending, status: "approved" } }];
    queues.trust_documents = [{ data: doc }];
    expect((await call(decide, "POST", { query: { id: REQ }, body: { decision: "approve" } }))._getStatusCode()).toBe(409);
    queues.trust_document_requests = [{ data: pending }];
    queues.trust_documents = [{ data: { ...doc, owner: "someone-else" } }];
    expect((await call(decide, "POST", { query: { id: REQ }, body: { decision: "approve" } }))._getStatusCode()).toBe(404);
  });
});

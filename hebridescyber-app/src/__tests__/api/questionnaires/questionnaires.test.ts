// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createMocks, type RequestMethod } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";
import ExcelJS from "exceljs";
import type { FakeQuery, FakeResult } from "@/lib/questionnaire/fakeSupabase";

const { authMock, gateMock, auditMock, rateMock, state } = vi.hoisted(() => ({
  authMock: vi.fn(),
  gateMock: vi.fn(),
  auditMock: vi.fn(),
  rateMock: vi.fn(),
  state: { resolve: (() => ({ data: [] })) as (q: FakeQuery) => FakeResult, calls: [] as FakeQuery[] },
}));

vi.mock("@/lib/apiAuth", async () => {
  const { fakeSupabase: fake } = await import("@/lib/questionnaire/fakeSupabase");
  const f = fake((q) => state.resolve(q));
  state.calls = f.calls;
  return { authenticateApiRequest: authMock, supabaseAdmin: f.client };
});
vi.mock("@/lib/planAccess", () => ({ planGate: gateMock }));
vi.mock("@/lib/audit", () => ({ logAuditEvent: auditMock }));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: rateMock }));
vi.mock("@/lib/questionnaire/evidence", async (orig) => {
  const real = await orig<typeof import("@/lib/questionnaire/evidence")>();
  return { ...real, loadEvidenceFacts: vi.fn().mockResolvedValue({ ...real.EMPTY_FACTS, m365CheckedAt: "2026-11-21T00:00:00Z" }) };
});

import listHandler from "@/pages/api/questionnaires";
import itemHandler from "@/pages/api/questionnaires/[id]";
import exportHandler from "@/pages/api/questionnaires/[id]/export";
import wordHandler from "@/pages/api/questionnaires/[id]/word";

const QID = "11111111-1111-4111-8111-111111111111";
const AID = "22222222-2222-4222-8222-222222222222";
const BID = "33333333-3333-4333-8333-333333333333";

async function call(handler: (req: NextApiRequest, res: NextApiResponse) => unknown, method: RequestMethod, opts: { body?: unknown; query?: Record<string, string> } = {}) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method, body: opts.body as Record<string, unknown>, query: opts.query });
  await handler(req, res);
  return res;
}

const csv = (text: string) => `data:text/csv;base64,${Buffer.from(text).toString("base64")}`;
const missing = { error: { message: "relation does not exist", code: "42P01" } };

beforeEach(() => {
  authMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
  gateMock.mockReset().mockResolvedValue("ok");
  auditMock.mockReset();
  rateMock.mockReset().mockResolvedValue({ allowed: true });
  state.resolve = () => ({ data: [] });
  state.calls.splice(0);
  vi.unstubAllEnvs();
});

describe("shared gates", () => {
  it.each([
    ["list", listHandler, {}],
    ["item", itemHandler, { id: QID }],
    ["export", exportHandler, { id: QID }],
    ["word", wordHandler, { id: QID }],
  ] as const)("%s: refuses wrong methods, no session, API keys and non-Pro plans", async (_n, handler, query) => {
    expect((await call(handler, "PUT", { query })).statusCode).toBe(405);
    const method = handler === wordHandler ? "POST" : "GET";
    authMock.mockResolvedValueOnce(null);
    expect((await call(handler, method, { query })).statusCode).toBe(401);
    authMock.mockResolvedValueOnce({ ownerId: "o", via: "key" });
    expect((await call(handler, method, { query })).statusCode).toBe(403);
    gateMock.mockResolvedValueOnce("denied");
    const denied = await call(handler, method, { query });
    expect(denied.statusCode).toBe(403);
    expect(denied._getJSONData().code).toBe("plan_required");
    gateMock.mockResolvedValueOnce("error");
    expect((await call(handler, method, { query })).statusCode).toBe(500);
  });

  it.each([itemHandler, exportHandler, wordHandler])("refuses an id that isn't a uuid", async (handler) => {
    expect((await call(handler, handler === wordHandler ? "POST" : "GET", { query: { id: "nope" } })).statusCode).toBe(400);
  });
});

describe("GET /api/questionnaires", () => {
  it("lists the owner's questionnaires with counts", async () => {
    state.resolve = () => ({ data: [{ id: QID, name: "Q.xlsx", source_format: "xlsx", created_at: "c", updated_at: "u", questionnaire_answers: [{ status: "accepted" }, { status: "draft" }] }, { id: "x", name: "R", source_format: "csv", created_at: "c", updated_at: "u", questionnaire_answers: null }] });
    const res = await call(listHandler, "GET");
    expect(res.statusCode).toBe(200);
    const body = res._getJSONData();
    expect(body.enabled).toBe(true);
    expect(body.aiAvailable).toBe(false);
    expect(body.questionnaires[0]).toEqual({ id: QID, name: "Q.xlsx", source_format: "xlsx", created_at: "c", updated_at: "u", counts: { draft: 1, needs_answer: 0, accepted: 1, rejected: 0, total: 2 } });
    expect(body.questionnaires[1].counts.total).toBe(0);
    expect(state.calls[0].filters).toContainEqual(["eq", "owner", "owner-1"]);
  });

  it("says disabled before the migration, and hides other errors", async () => {
    state.resolve = () => missing;
    expect((await call(listHandler, "GET"))._getJSONData()).toEqual({ questionnaires: [], enabled: false, aiAvailable: false });
    state.resolve = () => ({ error: { message: "column secret_col does not exist" } });
    const res = await call(listHandler, "GET");
    expect(res.statusCode).toBe(500);
    expect(JSON.stringify(res._getJSONData())).not.toContain("secret_col");
  });
});

describe("POST /api/questionnaires", () => {
  const file = "Ref,Question\n1,Is MFA enforced?\n2,Do staff get training?\n";

  it("previews the sheets with the detected question column", async () => {
    const res = await call(listHandler, "POST", { body: { fileName: "q.csv", dataUrl: csv(file), preview: true } });
    expect(res.statusCode).toBe(200);
    expect(res._getJSONData()).toEqual({
      format: "csv",
      sheets: [{ name: null, headers: ["Ref", "Question"], sample: [["1", "Is MFA enforced?"], ["2", "Do staff get training?"]], rowCount: 2, suggestedColumn: 1, confident: true, questions: 2 }],
    });
    expect(rateMock).toHaveBeenCalledWith("owner-1", "questionnaire-upload", { max: 30, windowSeconds: 3600 });
  });

  it("previews when no column is given", async () => {
    expect((await call(listHandler, "POST", { body: { fileName: "q.csv", dataUrl: csv(file) } }))._getJSONData().sheets).toHaveLength(1);
  });

  it("refuses bad input", async () => {
    expect((await call(listHandler, "POST", { body: { fileName: "q.pdf", dataUrl: csv(file) } }))._getJSONData().error).toBe("Upload an .xlsx or .csv file.");
    expect((await call(listHandler, "POST", { body: { dataUrl: csv(file) } })).statusCode).toBe(400);
    expect((await call(listHandler, "POST", { body: { fileName: "q.csv", dataUrl: "data:text/csv;base64,!!!" } })).statusCode).toBe(400);
    expect((await call(listHandler, "POST", { body: { fileName: "q.xlsx", dataUrl: csv(file) } }))._getJSONData().error).toMatch(/isn't an .xlsx/);
    expect((await call(listHandler, "POST", { body: { fileName: "q.csv", dataUrl: csv(file), questionColumn: 7 } }))._getJSONData().error).toBe("That column isn't in the sheet.");
    expect((await call(listHandler, "POST", { body: { fileName: "q.csv", dataUrl: csv(file), sheet: "Nope", questionColumn: 1 } }))._getJSONData().error).toBe("That sheet wasn't found in the file.");
  });

  it("rate-limits uploads", async () => {
    rateMock.mockResolvedValueOnce({ allowed: false, retryAfterSeconds: 60 });
    const res = await call(listHandler, "POST", { body: { fileName: "q.csv", dataUrl: csv(file), preview: true } });
    expect(res.statusCode).toBe(429);
    expect(res.getHeader("Retry-After")).toBe("60");
  });

  it("saves the questionnaire with a draft per question and audits it", async () => {
    state.resolve = (q) => (q.op === "select" && q.options?.head ? { count: 3 } : q.table === "questionnaires" && q.op === "insert" ? { data: { id: QID } } : { data: [] });
    const res = await call(listHandler, "POST", { body: { fileName: "q.csv", dataUrl: csv(file), sheet: null, questionColumn: 1 } });
    expect(res.statusCode).toBe(201);
    expect(res._getJSONData()).toEqual({ id: QID, questions: 2 });
    const answers = state.calls.find((c) => c.table === "questionnaire_answers" && c.op === "insert")!.values as Array<Record<string, unknown>>;
    expect(answers.map((a) => [a.topic, a.status])).toEqual([["mfa", "draft"], ["training", "needs_answer"]]);
    expect(auditMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "questionnaire.created", resourceId: QID }));
  });

  it("picks a named sheet of an .xlsx", async () => {
    const wb = new ExcelJS.Workbook();
    wb.addWorksheet("Intro").addRow(["Welcome", "to the form"]);
    const s = wb.addWorksheet("Questions");
    s.addRow(["Ref", "Question"]);
    s.addRow([1, "Is data encrypted in transit?"]);
    const dataUrl = `data:application/octet-stream;base64,${Buffer.from(await wb.xlsx.writeBuffer()).toString("base64")}`;
    state.resolve = (q) => (q.op === "select" && q.options?.head ? { count: 0 } : q.table === "questionnaires" && q.op === "insert" ? { data: { id: QID } } : { data: [] });
    const res = await call(listHandler, "POST", { body: { fileName: "q.xlsx", dataUrl, sheet: "Questions", questionColumn: 1 } });
    expect(res.statusCode).toBe(201);
  });

  it("enforces the questionnaire cap, and answers 503 or 500 when the count fails", async () => {
    state.resolve = () => ({ count: 200 });
    expect((await call(listHandler, "POST", { body: { fileName: "q.csv", dataUrl: csv(file), questionColumn: 1 } })).statusCode).toBe(409);
    state.resolve = () => missing;
    expect((await call(listHandler, "POST", { body: { fileName: "q.csv", dataUrl: csv(file), questionColumn: 1 } })).statusCode).toBe(503);
    state.resolve = () => ({ error: { message: "x" } });
    expect((await call(listHandler, "POST", { body: { fileName: "q.csv", dataUrl: csv(file), questionColumn: 1 } })).statusCode).toBe(500);
  });

  it("answers 400 for a column with no questions and 500 when the save fails", async () => {
    state.resolve = (q) => (q.op === "select" && q.options?.head ? { count: 0 } : { data: [] });
    expect((await call(listHandler, "POST", { body: { fileName: "q.csv", dataUrl: csv(file), questionColumn: 0 } })).statusCode).toBe(400);
    state.resolve = (q) => (q.op === "select" && q.options?.head ? { count: 0 } : q.op === "insert" ? { error: { message: "constraint questionnaires_name_check" } } : { data: [] });
    const res = await call(listHandler, "POST", { body: { fileName: "q.csv", dataUrl: csv(file), questionColumn: 1 } });
    expect(res.statusCode).toBe(500);
    expect(res._getJSONData().error).toBe("Couldn't save the questionnaire.");
  });
});

const answerRow = (over: Record<string, unknown> = {}) => ({ id: AID, status: "draft", answer: "Yes. MFA is in place.", draft_answer: "Yes. MFA is in place.", confidence: "high", ...over });
const qRow = { id: QID, name: "Q.xlsx", source_format: "xlsx", sheet_name: "S", headers: ["Ref", "Question"], rows: [["1", "Is MFA enforced?"]], question_column: 1, created_at: "c", updated_at: "u" };

describe("/api/questionnaires/[id]", () => {
  it("GET returns the questionnaire without its raw rows, with answers and counts", async () => {
    vi.stubEnv("AZURE_OPENAI_ENDPOINT", "https://x");
    vi.stubEnv("AZURE_OPENAI_KEY", "k");
    vi.stubEnv("AZURE_OPENAI_DEPLOYMENT", "d");
    state.resolve = (q) => (q.table === "questionnaires" ? { data: qRow } : { data: [{ ...answerRow(), row_index: 0 }] });
    const res = await call(itemHandler, "GET", { query: { id: QID } });
    const body = res._getJSONData();
    expect(body.questionnaire.rows).toBeUndefined();
    expect(body.questionnaire.rowCount).toBe(1);
    expect(body.counts.draft).toBe(1);
    expect(body.aiAvailable).toBe(true);
  });

  it("GET answers 404, 503 and 500", async () => {
    state.resolve = () => ({ data: null });
    expect((await call(itemHandler, "GET", { query: { id: QID } })).statusCode).toBe(404);
    state.resolve = () => missing;
    expect((await call(itemHandler, "GET", { query: { id: QID } })).statusCode).toBe(503);
    state.resolve = () => ({ error: { message: "x" } });
    expect((await call(itemHandler, "GET", { query: { id: QID } })).statusCode).toBe(500);
    state.resolve = (q) => (q.table === "questionnaires" ? { data: { ...qRow, rows: null } } : { data: [] });
    expect((await call(itemHandler, "GET", { query: { id: QID } }))._getJSONData().questionnaire.rowCount).toBe(0);
  });

  it("DELETE removes the owner's questionnaire and audits it", async () => {
    state.resolve = () => ({ data: [{ id: QID }] });
    expect((await call(itemHandler, "DELETE", { query: { id: QID } })).statusCode).toBe(204);
    expect(state.calls[0].filters).toEqual([["eq", "id", QID], ["eq", "owner", "owner-1"]]);
    expect(auditMock).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ action: "questionnaire.deleted" }));
    state.resolve = () => ({ data: [] });
    expect((await call(itemHandler, "DELETE", { query: { id: QID } })).statusCode).toBe(404);
    state.resolve = () => missing;
    expect((await call(itemHandler, "DELETE", { query: { id: QID } })).statusCode).toBe(503);
    state.resolve = () => ({ error: { message: "x" } });
    expect((await call(itemHandler, "DELETE", { query: { id: QID } })).statusCode).toBe(500);
  });

  it("PATCH accept: accepts answers with words in, skips empty ones", async () => {
    state.resolve = (q) => (q.table === "questionnaire_answers" && q.op === "select" ? { data: [answerRow(), answerRow({ id: BID, status: "needs_answer", answer: "", confidence: "none" })] } : { data: null });
    const res = await call(itemHandler, "PATCH", { query: { id: QID }, body: { action: "accept", answerIds: [AID, BID] } });
    expect(res._getJSONData()).toEqual({ updated: [AID], skipped: [BID] });
    const upd = state.calls.find((c) => c.table === "questionnaire_answers" && c.op === "update")!;
    expect(upd.values).toMatchObject({ status: "accepted", decided_by: "owner-1" });
    expect(upd.filters).toEqual([["eq", "questionnaire_id", QID], ["eq", "owner", "owner-1"], ["in", "id", [AID]]]);
    expect(state.calls.some((c) => c.table === "questionnaires" && c.op === "update")).toBe(true);
  });

  it("PATCH edit: saves the person's wording as accepted, marking it edited only when it differs", async () => {
    state.resolve = (q) => (q.op === "select" ? { data: [answerRow()] } : { data: null });
    await call(itemHandler, "PATCH", { query: { id: QID }, body: { action: "edit", answerIds: [AID], answer: "Yes, on every account." } });
    expect(state.calls.find((c) => c.op === "update")!.values).toMatchObject({ answer: "Yes, on every account.", status: "accepted", edited: true });
    state.calls.splice(0);
    await call(itemHandler, "PATCH", { query: { id: QID }, body: { action: "edit", answerIds: [AID], answer: "Yes. MFA is in place." } });
    expect(state.calls.find((c) => c.op === "update")!.values).toMatchObject({ edited: false });
  });

  it("PATCH reject and reset", async () => {
    state.resolve = (q) => (q.op === "select" ? { data: [answerRow({ answer: "Edited text" }), answerRow({ id: BID, confidence: "none", status: "accepted" })] } : { data: null });
    await call(itemHandler, "PATCH", { query: { id: QID }, body: { action: "reject", answerIds: [AID] } });
    expect(state.calls.find((c) => c.op === "update")!.values).toMatchObject({ status: "rejected" });
    state.calls.splice(0);
    const res = await call(itemHandler, "PATCH", { query: { id: QID }, body: { action: "reset", answerIds: [AID, BID] } });
    expect(res._getJSONData().updated).toEqual([AID, BID]);
    const updates = state.calls.filter((c) => c.table === "questionnaire_answers" && c.op === "update").map((c) => c.values);
    expect(updates).toEqual([
      expect.objectContaining({ status: "draft", edited: false, ai_worded: false, decided_at: null }),
      { answer: "Yes. MFA is in place." },
      expect.objectContaining({ status: "needs_answer", answer: "" }),
    ]);
  });

  it("PATCH refuses bad bodies, unknown answers, and hides errors", async () => {
    expect((await call(itemHandler, "PATCH", { query: { id: QID }, body: { action: "edit", answerIds: [AID] } })).statusCode).toBe(400);
    expect((await call(itemHandler, "PATCH", { query: { id: QID }, body: { action: "accept", answerIds: ["x"] } })).statusCode).toBe(400);
    state.resolve = () => ({ data: [] });
    expect((await call(itemHandler, "PATCH", { query: { id: QID }, body: { action: "accept", answerIds: [AID] } })).statusCode).toBe(404);
    state.resolve = () => missing;
    expect((await call(itemHandler, "PATCH", { query: { id: QID }, body: { action: "accept", answerIds: [AID] } })).statusCode).toBe(503);
    state.resolve = () => ({ error: { message: "x" } });
    expect((await call(itemHandler, "PATCH", { query: { id: QID }, body: { action: "accept", answerIds: [AID] } })).statusCode).toBe(500);
    state.resolve = (q) => (q.op === "select" ? { data: [answerRow()] } : { error: { message: "update failed" } });
    expect((await call(itemHandler, "PATCH", { query: { id: QID }, body: { action: "reject", answerIds: [AID] } })).statusCode).toBe(500);
    state.resolve = (q) => (q.op === "select" ? { data: [answerRow({ answer: "different" })] } : q.values && (q.values as { answer?: string }).answer ? { error: { message: "per-row failed" } } : { data: null });
    expect((await call(itemHandler, "PATCH", { query: { id: QID }, body: { action: "reset", answerIds: [AID] } })).statusCode).toBe(500);
  });
});

describe("GET /api/questionnaires/[id]/export", () => {
  beforeEach(() => {
    state.resolve = (q) => (q.table === "questionnaires" ? { data: qRow } : { data: [{ id: AID, row_index: 0, question: "Is MFA enforced?", draft_answer: "Yes.", answer: "Yes.", evidence: [], confidence: "high", status: "accepted", edited: false }] });
  });

  it("downloads an .xlsx by default and a CSV on request", async () => {
    const x = await call(exportHandler, "GET", { query: { id: QID } });
    expect(x.statusCode).toBe(200);
    expect(x.getHeader("Content-Type")).toBe("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    expect(x.getHeader("Content-Disposition")).toBe('attachment; filename="Q - draft answers.xlsx"');
    const c = await call(exportHandler, "GET", { query: { id: QID, format: "csv" } });
    expect(c._getData()).toContain("1,Is MFA enforced?,Yes.,,Accepted");
  });

  it("refuses an unknown format, and answers 404, 503 and 500", async () => {
    expect((await call(exportHandler, "GET", { query: { id: QID, format: "pdf" } })).statusCode).toBe(400);
    state.resolve = () => ({ data: null });
    expect((await call(exportHandler, "GET", { query: { id: QID } })).statusCode).toBe(404);
    state.resolve = () => missing;
    expect((await call(exportHandler, "GET", { query: { id: QID } })).statusCode).toBe(503);
    state.resolve = () => ({ error: { message: "x" } });
    expect((await call(exportHandler, "GET", { query: { id: QID } })).statusCode).toBe(500);
    state.resolve = (q) => (q.table === "questionnaires" ? { data: { ...qRow, headers: null } } : { data: [] });
    expect((await call(exportHandler, "GET", { query: { id: QID } })).statusCode).toBe(500);
  });
});

describe("POST /api/questionnaires/[id]/word", () => {
  const pending = [{ id: AID, question: "Is MFA enforced?", answer: "Yes. MFA is in place.", evidence: [{ source: "m365", label: "Microsoft 365 check", detail: "ok", date: "2026-11-21" }] }, { id: BID, question: "Is RDP open?", answer: "No remote access services are open.", evidence: null }];

  it("leaves drafts untouched when Azure OpenAI isn't configured", async () => {
    state.resolve = () => ({ data: pending, count: 2 });
    const res = await call(wordHandler, "POST", { query: { id: QID } });
    expect(res._getJSONData()).toEqual({ status: "not_configured", worded: 0, remaining: 2 });
    expect(state.calls.some((c) => c.op === "update")).toBe(false);
    const q = state.calls[0];
    expect(q.filters).toEqual(expect.arrayContaining([["eq", "status", "draft"], ["eq", "ai_checked", false], ["is", "reused_from", null], ["neq", "confidence", "none"]]));
  });

  it("rewords drafts and marks every sent draft as checked", async () => {
    vi.stubEnv("AZURE_OPENAI_ENDPOINT", "https://x");
    vi.stubEnv("AZURE_OPENAI_KEY", "k");
    vi.stubEnv("AZURE_OPENAI_DEPLOYMENT", "d");
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ choices: [{ message: { content: JSON.stringify({ answers: [{ id: AID, answer: "Yes, we enforce MFA on every account." }] }) } }] }) });
    vi.stubGlobal("fetch", fetchMock);
    state.resolve = (q) => (q.op === "select" ? { data: pending, count: 12 } : { data: null });
    const res = await call(wordHandler, "POST", { query: { id: QID } });
    expect(res._getJSONData()).toEqual({ status: "ok", worded: 1, remaining: 10 });
    const updates = state.calls.filter((c) => c.op === "update").map((c) => c.values);
    expect(updates).toEqual([
      expect.objectContaining({ answer: "Yes, we enforce MFA on every account.", ai_checked: true, ai_worded: true }),
      expect.objectContaining({ ai_checked: true }),
    ]);
    expect(updates[1]).not.toHaveProperty("answer");
    vi.unstubAllGlobals();
  });

  it("answers ok with nothing to do, logs AI errors without failing, and handles DB errors", async () => {
    state.resolve = () => ({ data: [], count: 0 });
    expect((await call(wordHandler, "POST", { query: { id: QID } }))._getJSONData()).toEqual({ status: "ok", worded: 0, remaining: 0 });

    vi.stubEnv("AZURE_OPENAI_ENDPOINT", "https://x");
    vi.stubEnv("AZURE_OPENAI_KEY", "k");
    vi.stubEnv("AZURE_OPENAI_DEPLOYMENT", "d");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 500 }));
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    state.resolve = () => ({ data: pending, count: null });
    expect((await call(wordHandler, "POST", { query: { id: QID } }))._getJSONData()).toEqual({ status: "error", worded: 0, remaining: 2 });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ choices: [{ message: { content: '{"answers":[]}' } }] }) }));
    state.resolve = (q) => (q.op === "select" ? { data: pending, count: null } : { error: { message: "x" } });
    expect((await call(wordHandler, "POST", { query: { id: QID } })).statusCode).toBe(500);
    vi.unstubAllGlobals();

    state.resolve = () => missing;
    expect((await call(wordHandler, "POST", { query: { id: QID } })).statusCode).toBe(503);
    state.resolve = () => ({ error: { message: "x" } });
    expect((await call(wordHandler, "POST", { query: { id: QID } })).statusCode).toBe(500);
    rateMock.mockResolvedValueOnce({ allowed: false, retryAfterSeconds: 5 });
    expect((await call(wordHandler, "POST", { query: { id: QID } })).statusCode).toBe(429);
    errSpy.mockRestore();
  });
});

// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";
import ExcelJS from "exceljs";
import { fakeSupabase, filterValue, type FakeQuery, type FakeResult } from "./fakeSupabase";
import { EMPTY_FACTS } from "./evidence";

const { factsMock } = vi.hoisted(() => ({ factsMock: vi.fn() }));
vi.mock("./evidence", async (orig) => ({ ...(await orig<typeof import("./evidence")>()), loadEvidenceFacts: factsMock }));

import { buildExport, createQuestionnaire, draftAll, exportAnswer, exportFileName, loadPriorAnswers, loadQuestionnaire, summarise, type AnswerRow, type QuestionnaireRow } from "./store";

const answer = (over: Partial<AnswerRow> = {}): AnswerRow => ({
  id: "a1",
  row_index: 0,
  question: "Is MFA enforced?",
  topic: "mfa",
  draft_answer: "Yes. MFA is in place.",
  answer: "Yes. MFA is in place.",
  evidence: [{ source: "m365", label: "Microsoft 365 check", detail: "No accounts without MFA.", date: "2026-11-21" }],
  confidence: "high",
  status: "accepted",
  edited: false,
  ai_worded: false,
  reused_from: null,
  decided_at: "2026-11-22T00:00:00Z",
  updated_at: "2026-11-22T00:00:00Z",
  ...over,
});

const questionnaire: QuestionnaireRow = {
  id: "q1",
  name: "Insurer: renewal/2026.xlsx",
  source_format: "xlsx",
  sheet_name: "Security",
  headers: ["Ref", "Question"],
  rows: [["1", "Is MFA enforced?"], ["2", "Do staff get training?"], ["3", "Are backups tested?"], ["", "Section"]],
  question_column: 1,
  created_at: "2026-11-22T00:00:00Z",
  updated_at: "2026-11-22T00:00:00Z",
};

describe("pure helpers", () => {
  it("drafts every question, reusing an accepted answer", () => {
    const out = draftAll([{ rowIndex: 0, question: "Do staff get security training?" }, { rowIndex: 2, question: "Is MFA enforced?" }], EMPTY_FACTS, [
      { id: "p", question: "Do staff get security training?", topic: "training", answer: "Yes, annually.", evidence: [], decidedAt: null, questionnaireName: "Old" },
    ]);
    expect(out[0].draft).toMatchObject({ status: "draft", reusedFrom: "p", answer: "Yes, annually." });
    expect(out[1]).toMatchObject({ rowIndex: 2, draft: { status: "needs_answer" } });
  });

  it("exports only what a person decided as final, labelling the rest", () => {
    expect(exportAnswer(answer())).toEqual({ rowIndex: 0, answer: "Yes. MFA is in place.", evidence: "Microsoft 365 check (2026-11-21): No accounts without MFA.", status: "Accepted" });
    expect(exportAnswer(answer({ status: "rejected" })).answer).toBe("");
    expect(exportAnswer(answer({ status: "needs_answer", answer: "", evidence: null as unknown as [] }))).toMatchObject({ answer: "", evidence: "", status: "Needs your answer" });
    expect(exportAnswer(answer({ status: "draft", answer: "" }))).toMatchObject({ answer: "Yes. MFA is in place.", status: "Draft, not reviewed" });
    expect(exportAnswer(answer({ status: "needs_answer", answer: "Typed but not saved" })).answer).toBe("Typed but not saved");
  });

  it("makes a safe file name", () => {
    expect(exportFileName("Insurer: renewal/2026.xlsx", "csv")).toBe("Insurer renewal2026 - draft answers.csv");
    expect(exportFileName("***.csv", "xlsx")).toBe("questionnaire - draft answers.xlsx");
  });

  it("counts statuses", () => {
    expect(summarise([{ status: "accepted" }, { status: "draft" }, { status: "draft" }, { status: "needs_answer" }])).toEqual({ draft: 2, needs_answer: 1, accepted: 1, rejected: 0, total: 4 });
  });
});

describe("buildExport", () => {
  it("builds a CSV with the disclaimer last", async () => {
    const out = await buildExport(questionnaire, [answer()], "csv");
    expect(out.contentType).toBe("text/csv; charset=utf-8");
    expect(out.fileName).toBe("Insurer renewal2026 - draft answers.csv");
    const text = out.body as string;
    expect(text).toContain("Ref,Question,Answer,Evidence,Status");
    expect(text).toContain("1,Is MFA enforced?,Yes. MFA is in place.");
    expect(text.trim().split("\r\n").pop()).toMatch(/^Draft answers prepared by Hebrides Cyber/);
  });

  it("builds an .xlsx", async () => {
    const out = await buildExport(questionnaire, [answer({ row_index: 1, status: "draft" })], "xlsx");
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(out.body as unknown as ArrayBuffer);
    expect(wb.worksheets[0].getRow(3).getCell(5).value).toBe("Draft, not reviewed");
  });
});

describe("database calls", () => {
  let results: (q: FakeQuery) => FakeResult;

  beforeEach(() => {
    factsMock.mockReset().mockResolvedValue({ ...EMPTY_FACTS, m365CheckedAt: "2026-11-21T00:00:00Z" });
    results = () => ({ data: [] });
  });

  it("loads prior accepted answers with their questionnaire name", async () => {
    results = () => ({ data: [{ id: "p", question: "Q?", topic: null, answer: "A", evidence: null, decided_at: null, questionnaires: null }, { id: "r", question: "R?", topic: "mfa", answer: "B", evidence: [], decided_at: "2026-01-01", questionnaires: { name: "Old.xlsx" } }] });
    const { client, calls } = fakeSupabase((q) => results(q));
    const prior = await loadPriorAnswers(client, "o");
    expect(prior.map((p) => p.questionnaireName)).toEqual(["an earlier questionnaire", "Old.xlsx"]);
    expect(prior[0].evidence).toEqual([]);
    expect(filterValue(calls[0], "status")).toBe("accepted");
    results = () => ({ error: { message: "x" } });
    expect(await loadPriorAnswers(fakeSupabase((q) => results(q)).client, "o")).toEqual([]);
  });

  it("creates a questionnaire with a draft for each question row only", async () => {
    const { client, calls } = fakeSupabase((q) => (q.table === "questionnaires" && q.op === "insert" ? { data: { id: "new-q" } } : { data: [] }));
    const res = await createQuestionnaire(client, "owner-1", { name: "Q.xlsx", format: "xlsx", table: { name: "Security", headers: questionnaire.headers, rows: questionnaire.rows }, questionColumn: 1 });
    expect(res).toEqual({ ok: true, id: "new-q", questions: 3 });
    const inserted = calls.find((c) => c.table === "questionnaire_answers" && c.op === "insert")!.values as Array<Record<string, unknown>>;
    expect(inserted.map((r) => r.row_index)).toEqual([0, 1, 2]);
    expect(inserted[0]).toMatchObject({ owner: "owner-1", questionnaire_id: "new-q", status: "draft", confidence: "high", topic: "mfa" });
    expect(inserted[1]).toMatchObject({ status: "needs_answer", answer: "", draft_answer: "Needs your answer" });
  });

  it("refuses a sheet too large to store", async () => {
    const { client, calls } = fakeSupabase(() => ({ data: [] }));
    const rows = Array.from({ length: 800 }, () => ["Is this a long enough question to count?", "x".repeat(4000)]);
    expect(await createQuestionnaire(client, "o", { name: "Q.csv", format: "csv", table: { name: null, headers: ["Q", "Notes"], rows }, questionColumn: 0 })).toMatchObject({ ok: false, status: 400 });
    expect(calls).toHaveLength(0);
  });

  it("refuses a column with no questions", async () => {
    const { client } = fakeSupabase(() => ({ data: [] }));
    expect(await createQuestionnaire(client, "o", { name: "Q.csv", format: "csv", table: { name: null, headers: ["Ref"], rows: [["1"], ["2"]] }, questionColumn: 0 })).toMatchObject({ ok: false, status: 400 });
  });

  it("reports a failed save, and removes the questionnaire if its answers fail", async () => {
    const failInsert = fakeSupabase((q) => (q.table === "questionnaires" && q.op === "insert" ? { error: { message: "x" } } : { data: [] }));
    expect(await createQuestionnaire(failInsert.client, "o", { name: "Q", format: "csv", table: { name: null, headers: questionnaire.headers, rows: questionnaire.rows }, questionColumn: 1 })).toMatchObject({ ok: false, status: 500 });

    const failAnswers = fakeSupabase((q) =>
      q.table === "questionnaires" && q.op === "insert" ? { data: { id: "q9" } } : q.table === "questionnaire_answers" && q.op === "insert" ? { error: { message: "y" } } : { data: [] },
    );
    const r = await createQuestionnaire(failAnswers.client, "o", { name: "Q", format: "csv", table: { name: null, headers: questionnaire.headers, rows: questionnaire.rows }, questionColumn: 1 });
    expect(r).toMatchObject({ ok: false, status: 500, error: "Couldn't save the drafted answers." });
    const del = failAnswers.calls.find((c) => c.op === "delete")!;
    expect(del.filters).toEqual([["eq", "id", "q9"], ["eq", "owner", "o"]]);
  });

  it("loads a questionnaire and its answers, scoped to the owner", async () => {
    const { client, calls } = fakeSupabase((q) => (q.table === "questionnaires" ? { data: questionnaire } : { data: [answer()] }));
    const r = await loadQuestionnaire(client, "o", "q1");
    expect(r.ok && r.answers).toHaveLength(1);
    for (const c of calls) expect(c.filters).toContainEqual(["eq", "owner", "o"]);
  });

  it("reports not found and read errors", async () => {
    expect(await loadQuestionnaire(fakeSupabase(() => ({ data: null })).client, "o", "q1")).toEqual({ ok: false, notFound: true });
    expect(await loadQuestionnaire(fakeSupabase(() => ({ error: { message: "x" } })).client, "o", "q1")).toMatchObject({ ok: false, notFound: false });
    const answersFail = fakeSupabase((q) => (q.table === "questionnaires" ? { data: questionnaire } : { error: { message: "y" } }));
    expect(await loadQuestionnaire(answersFail.client, "o", "q1")).toMatchObject({ ok: false, notFound: false });
  });
});

// Saving, loading and exporting questionnaires (migration 087). Server-only:
// every read and write uses the service role, scoped to the caller's owner id.
import type { SupabaseClient } from "@supabase/supabase-js";
import { loadEvidenceFacts, type EvidenceFacts } from "./evidence";
import { applyReuse, type PriorAnswer } from "./reuse";
import { exportRows, questionRows, toCsv, toXlsx, type SheetTable, type SourceFormat } from "./spreadsheet";
import { draftFromEvidence } from "./topics";
import { DRAFT_DISCLAIMER, citationLine, statusLabel, type AnswerStatus, type Confidence, type DraftAnswer, type EvidenceCitation } from "./types";

/** How many earlier accepted answers to consider for reuse. */
const PRIOR_LIMIT = 500;
export const MAX_QUESTIONNAIRES = 200;
/** Just under migration 087's octet_length(rows::text) <= 3000000 check. */
const MAX_ROWS_BYTES = 2_900_000;
export const NOT_ENABLED = "Questionnaires aren't enabled on this server yet (database migration 087 pending).";

export type QuestionnaireRow = {
  id: string;
  name: string;
  source_format: SourceFormat;
  sheet_name: string | null;
  headers: string[];
  rows: string[][];
  question_column: number;
  created_at: string;
  updated_at: string;
};

export type AnswerRow = {
  id: string;
  row_index: number;
  question: string;
  topic: string | null;
  draft_answer: string;
  answer: string;
  evidence: EvidenceCitation[];
  confidence: Confidence;
  status: AnswerStatus;
  edited: boolean;
  ai_worded: boolean;
  reused_from: string | null;
  decided_at: string | null;
  updated_at: string;
};

export const ANSWER_COLUMNS = "id, row_index, question, topic, draft_answer, answer, evidence, confidence, status, edited, ai_worded, reused_from, decided_at, updated_at";

/** Pure: a draft for every question row, from the evidence and earlier accepted answers. */
export function draftAll(questions: Array<{ rowIndex: number; question: string }>, facts: EvidenceFacts, prior: PriorAnswer[]): Array<{ rowIndex: number; question: string; draft: DraftAnswer }> {
  return questions.map(({ rowIndex, question }) => ({ rowIndex, question, draft: applyReuse(draftFromEvidence(question, facts), question, prior) }));
}

/** The owner's accepted answers, newest first, for reuse. Empty when none or unreadable. */
export async function loadPriorAnswers(supabaseAdmin: SupabaseClient, ownerId: string): Promise<PriorAnswer[]> {
  const { data, error } = await supabaseAdmin
    .from("questionnaire_answers")
    .select("id, question, topic, answer, evidence, decided_at, questionnaires(name)")
    .eq("owner", ownerId)
    .eq("status", "accepted")
    .order("decided_at", { ascending: false })
    .limit(PRIOR_LIMIT);
  if (error || !data) return [];
  return (data as unknown as Array<{ id: string; question: string; topic: string | null; answer: string; evidence: EvidenceCitation[] | null; decided_at: string | null; questionnaires: { name?: string } | null }>).map((r) => ({
    id: r.id,
    question: r.question,
    topic: r.topic,
    answer: r.answer,
    evidence: Array.isArray(r.evidence) ? r.evidence : [],
    decidedAt: r.decided_at,
    questionnaireName: r.questionnaires?.name ?? "an earlier questionnaire",
  }));
}

export type CreateResult = { ok: true; id: string; questions: number } | { ok: false; status: number; error: string; cause?: unknown };

/** Save an uploaded questionnaire and draft an answer to each of its questions. */
export async function createQuestionnaire(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  input: { name: string; format: SourceFormat; table: SheetTable; questionColumn: number },
  now: Date = new Date(),
): Promise<CreateResult> {
  const questions = questionRows(input.table.rows, input.questionColumn);
  if (!questions.length) return { ok: false, status: 400, error: "No questions were found in that column. Pick the column that holds the questions." };
  // Migration 087 caps the stored rows at 3 MB; say so rather than fail the insert.
  if (Buffer.byteLength(JSON.stringify(input.table.rows)) > MAX_ROWS_BYTES) return { ok: false, status: 400, error: "That sheet is too large to store. Remove columns you don't need and upload it again." };

  const [facts, prior] = await Promise.all([loadEvidenceFacts(supabaseAdmin, ownerId, now), loadPriorAnswers(supabaseAdmin, ownerId)]);
  const drafts = draftAll(questions, facts, prior);

  const { data, error } = await supabaseAdmin
    .from("questionnaires")
    .insert({
      owner: ownerId,
      name: input.name,
      source_format: input.format,
      sheet_name: input.table.name,
      headers: input.table.headers,
      rows: input.table.rows,
      question_column: input.questionColumn,
      created_by: ownerId,
    })
    .select("id")
    .single();
  if (error || !data) return { ok: false, status: 500, error: "Couldn't save the questionnaire.", cause: error };
  const id = (data as { id: string }).id;

  const rows = drafts.map(({ rowIndex, question, draft }) => ({
    questionnaire_id: id,
    owner: ownerId,
    row_index: rowIndex,
    question: question.slice(0, 4000),
    topic: draft.topic,
    draft_answer: draft.answer,
    answer: draft.status === "needs_answer" ? "" : draft.answer,
    evidence: draft.evidence,
    confidence: draft.confidence,
    status: draft.status,
    reused_from: draft.reusedFrom,
  }));
  for (let i = 0; i < rows.length; i += 500) {
    const { error: insErr } = await supabaseAdmin.from("questionnaire_answers").insert(rows.slice(i, i + 500));
    if (insErr) {
      // Don't leave a questionnaire with half its answers.
      await supabaseAdmin.from("questionnaires").delete().eq("id", id).eq("owner", ownerId);
      return { ok: false, status: 500, error: "Couldn't save the drafted answers.", cause: insErr };
    }
  }
  return { ok: true, id, questions: rows.length };
}

export async function loadQuestionnaire(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  id: string,
): Promise<{ ok: true; questionnaire: QuestionnaireRow; answers: AnswerRow[] } | { ok: false; notFound: boolean; error?: unknown }> {
  const { data, error } = await supabaseAdmin
    .from("questionnaires")
    .select("id, name, source_format, sheet_name, headers, rows, question_column, created_at, updated_at")
    .eq("id", id)
    .eq("owner", ownerId)
    .maybeSingle();
  if (error) return { ok: false, notFound: false, error };
  if (!data) return { ok: false, notFound: true };
  const answers = await supabaseAdmin.from("questionnaire_answers").select(ANSWER_COLUMNS).eq("questionnaire_id", id).eq("owner", ownerId).order("row_index", { ascending: true });
  if (answers.error) return { ok: false, notFound: false, error: answers.error };
  return { ok: true, questionnaire: data as QuestionnaireRow, answers: (answers.data ?? []) as AnswerRow[] };
}

/** Pure: what one answer contributes to the export. Only a person's accepted answer is final. */
export function exportAnswer(a: AnswerRow): { rowIndex: number; answer: string; evidence: string; status: string } {
  const answer = a.status === "rejected" ? "" : a.status === "needs_answer" ? (a.answer || "") : a.answer || a.draft_answer;
  return {
    rowIndex: a.row_index,
    answer,
    evidence: (Array.isArray(a.evidence) ? a.evidence : []).map(citationLine).join("\n"),
    status: statusLabel(a.status, a.edited),
  };
}

/** Pure: a safe download file name for the export. */
export function exportFileName(name: string, format: SourceFormat): string {
  const base = name.replace(/\.(xlsx|csv)$/i, "").replace(/[^A-Za-z0-9 _.-]+/g, "").trim().slice(0, 80) || "questionnaire";
  return `${base} - draft answers.${format}`;
}

export async function buildExport(questionnaire: QuestionnaireRow, answers: AnswerRow[], format: SourceFormat): Promise<{ body: Buffer | string; contentType: string; fileName: string }> {
  const rows = exportRows(questionnaire.headers, questionnaire.rows, answers.map(exportAnswer), DRAFT_DISCLAIMER, format);
  if (format === "csv") return { body: toCsv(rows), contentType: "text/csv; charset=utf-8", fileName: exportFileName(questionnaire.name, "csv") };
  return {
    body: await toXlsx(questionnaire.sheet_name, rows),
    contentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    fileName: exportFileName(questionnaire.name, "xlsx"),
  };
}

/** Pure: the counts the list and the review page show. */
export function summarise(answers: Array<Pick<AnswerRow, "status">>): Record<AnswerStatus, number> & { total: number } {
  const out = { draft: 0, needs_answer: 0, accepted: 0, rejected: 0, total: answers.length };
  for (const a of answers) out[a.status]++;
  return out;
}

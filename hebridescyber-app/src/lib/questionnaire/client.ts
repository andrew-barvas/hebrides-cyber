// Browser-side calls to /api/questionnaires. Client-safe: no exceljs, no
// Supabase admin client.
import type { AnswerStatus, Confidence, EvidenceCitation } from "./types";

export type Counts = Record<AnswerStatus, number> & { total: number };
export type QuestionnaireSummary = { id: string; name: string; source_format: "xlsx" | "csv"; created_at: string; updated_at: string; counts: Counts };
export type SheetPreview = { name: string | null; headers: string[]; sample: string[][]; rowCount: number; suggestedColumn: number; confident: boolean; questions: number };
export type ReviewAnswer = {
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
};
export type QuestionnaireDetail = {
  questionnaire: { id: string; name: string; source_format: "xlsx" | "csv"; sheet_name: string | null; headers: string[]; question_column: number; created_at: string; rowCount: number };
  answers: ReviewAnswer[];
  counts: Counts;
  aiAvailable: boolean;
};

async function call<T>(token: string, path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, ...(init.body ? { "Content-Type": "application/json" } : {}), ...(init.headers ?? {}) },
  });
  if (res.status === 204) return undefined as T;
  const body = (await res.json().catch(() => ({}))) as { error?: string };
  if (!res.ok) throw new Error(body.error ?? (res.status === 429 ? "Too many requests. Try again in a few minutes." : `Request failed (${res.status}).`));
  return body as T;
}

export function readFileAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error("The file couldn't be read."));
    reader.readAsDataURL(file);
  });
}

export const listQuestionnaires = (token: string) => call<{ questionnaires: QuestionnaireSummary[]; enabled: boolean; aiAvailable: boolean }>(token, "/api/questionnaires");

export const previewQuestionnaire = (token: string, fileName: string, dataUrl: string) =>
  call<{ format: "xlsx" | "csv"; sheets: SheetPreview[] }>(token, "/api/questionnaires", { method: "POST", body: JSON.stringify({ fileName, dataUrl, preview: true }) });

export const createQuestionnaire = (token: string, input: { fileName: string; dataUrl: string; sheet: string | null; questionColumn: number }) =>
  call<{ id: string; questions: number }>(token, "/api/questionnaires", { method: "POST", body: JSON.stringify(input) });

export const getQuestionnaire = (token: string, id: string) => call<QuestionnaireDetail>(token, `/api/questionnaires/${encodeURIComponent(id)}`);

export const reviewAnswers = (token: string, id: string, body: { action: "accept" | "reject" | "reset"; answerIds: string[] } | { action: "edit"; answerIds: [string]; answer: string }) =>
  call<{ updated: string[]; skipped: string[] }>(token, `/api/questionnaires/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(body) });

export const deleteQuestionnaire = (token: string, id: string) => call<void>(token, `/api/questionnaires/${encodeURIComponent(id)}`, { method: "DELETE" });

export const wordWithAi = (token: string, id: string) =>
  call<{ status: "ok" | "not_configured" | "error"; worded: number; remaining: number }>(token, `/api/questionnaires/${encodeURIComponent(id)}/word`, { method: "POST" });

export async function downloadExport(token: string, id: string, format: "xlsx" | "csv"): Promise<{ blob: Blob; fileName: string }> {
  const res = await fetch(`/api/questionnaires/${encodeURIComponent(id)}/export?format=${format}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? `The export failed (${res.status}).`);
  }
  const disposition = res.headers.get("Content-Disposition") ?? "";
  const fileName = /filename="([^"]+)"/.exec(disposition)?.[1] ?? `questionnaire.${format}`;
  return { blob: await res.blob(), fileName };
}

export function saveBlob(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

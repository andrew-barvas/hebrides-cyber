// Reading and writing questionnaire spreadsheets (.xlsx via exceljs, .csv by
// hand). Server-only: exceljs is large and never belongs in a browser bundle.
//
// A questionnaire is read into a plain table: a header row and the data rows
// under it, every cell as text. The export returns those rows unchanged, with
// Answer, Evidence and Status columns appended.
import ExcelJS from "exceljs";

export const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
export const MAX_ROWS = 5000;
export const MAX_COLUMNS = 200;
export const MAX_SHEETS = 20;
const MAX_CELL_CHARS = 4000;
/** Title rows above the real header are common; look this far down for it. */
const HEADER_SCAN_ROWS = 15;

export type SourceFormat = "xlsx" | "csv";

export type SheetTable = {
  name: string | null;
  headers: string[];
  rows: string[][];
};

export type ParseResult = { ok: true; format: SourceFormat; sheets: SheetTable[] } | { ok: false; error: string };

const clip = (s: string) => (s.length > MAX_CELL_CHARS ? s.slice(0, MAX_CELL_CHARS) : s);

/** Pure: the format a file name says it is, or null. */
export function formatFromName(name: string): SourceFormat | null {
  const ext = name.toLowerCase().split(".").pop();
  return ext === "xlsx" ? "xlsx" : ext === "csv" ? "csv" : null;
}

/** Pure: the bytes of a base64 data URL (or bare base64) upload, or an error. */
export function decodeUpload(dataUrl: string): { ok: true; bytes: Uint8Array } | { ok: false; error: string } {
  const m = /^data:[\w.+/-]*(;[\w=.-]+)*;base64,/.exec(dataUrl);
  const b64 = m ? dataUrl.slice(m[0].length) : dataUrl;
  if (!/^[A-Za-z0-9+/\s]*={0,2}\s*$/.test(b64)) return { ok: false, error: "The upload wasn't readable. Try choosing the file again." };
  const bytes = new Uint8Array(Buffer.from(b64, "base64"));
  if (!bytes.byteLength) return { ok: false, error: "The file is empty." };
  if (bytes.byteLength > MAX_UPLOAD_BYTES) return { ok: false, error: "The file is larger than 5 MB." };
  return { ok: true, bytes };
}

// ---------------------------------------------------------------- CSV

/** Pure: the delimiter the first line uses most, outside quotes. */
export function detectDelimiter(text: string): string {
  const firstLine: string[] = [];
  let inQuotes = false;
  for (const ch of text) {
    if (ch === '"') inQuotes = !inQuotes;
    else if (!inQuotes && (ch === "\n" || ch === "\r")) break;
    firstLine.push(inQuotes ? "" : ch);
  }
  const line = firstLine.join("");
  const counts = [",", ";", "\t"].map((d) => [d, line.split(d).length - 1] as const);
  counts.sort((a, b) => b[1] - a[1]);
  return counts[0][1] > 0 ? counts[0][0] : ",";
}

/** Pure: RFC 4180 CSV to rows of cells. Handles a BOM, quoted fields, "" escapes and CRLF. */
export function parseCsv(input: string): string[][] {
  const text = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
  const delimiter = detectDelimiter(text);
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          cell += '"';
          i++;
        } else inQuotes = false;
      } else cell += ch;
      continue;
    }
    if (ch === '"' && cell === "") inQuotes = true;
    else if (ch === delimiter) {
      row.push(cell);
      cell = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
    } else cell += ch;
  }
  if (cell !== "" || row.length) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

/** Pure: a cell that a spreadsheet would run as a formula, made inert (CWE-1236). */
export function neutraliseFormula(value: string): string {
  return /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
}

function csvCell(value: string): string {
  return /[",\r\n;]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

/** Pure: rows to CSV text, CRLF line endings, with a BOM so Excel reads UTF-8. */
export function toCsv(rows: string[][]): string {
  return "﻿" + rows.map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

// ---------------------------------------------------------------- tables

/** Pure: exceljs cell values (rich text, formulas, links, dates) as plain text. */
export function cellText(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? "" : value.toISOString().slice(0, 10);
  if (typeof value === "object") {
    const v = value as { richText?: Array<{ text?: string }>; text?: unknown; result?: unknown; error?: unknown };
    if (Array.isArray(v.richText)) return v.richText.map((r) => r.text ?? "").join("");
    if (v.text !== undefined) return cellText(v.text);
    if (v.result !== undefined) return cellText(v.result);
  }
  return "";
}

const nonEmpty = (row: string[]) => row.filter((c) => c.trim() !== "").length;

/**
 * Pure: split raw rows into a header row and data rows. The header is the
 * first row with two or more filled cells, unless a row within the first
 * few names a "question" column, which wins: questionnaires often open with
 * a title block.
 */
export function toTable(name: string | null, raw: string[][]): SheetTable {
  const trimmed = raw.map((r) => r.slice(0, MAX_COLUMNS).map((c) => clip(c.replace(/\u0000/g, "").trim())));
  const window = trimmed.slice(0, HEADER_SCAN_ROWS);
  let headerIdx = window.findIndex((r) => nonEmpty(r) >= 2 && r.some((c) => /question|requirement|control/i.test(c) && c.length <= 60));
  if (headerIdx < 0) headerIdx = window.findIndex((r) => nonEmpty(r) >= 2);
  if (headerIdx < 0) headerIdx = window.findIndex((r) => nonEmpty(r) >= 1);
  if (headerIdx < 0) return { name, headers: [], rows: [] };
  const body = trimmed.slice(headerIdx + 1);
  while (body.length && nonEmpty(body[body.length - 1]) === 0) body.pop();
  const width = Math.min(MAX_COLUMNS, Math.max(trimmed[headerIdx].length, ...body.map((r) => r.length)));
  const pad = (r: string[]) => Array.from({ length: width }, (_, i) => r[i] ?? "");
  const headers = pad(trimmed[headerIdx]).map((h, i) => h || `Column ${i + 1}`);
  return { name, headers, rows: body.slice(0, MAX_ROWS).map(pad) };
}

/** Parse an uploaded questionnaire. Never throws: a broken file is `ok: false`. */
export async function parseQuestionnaire(bytes: Uint8Array, format: SourceFormat): Promise<ParseResult> {
  if (bytes.byteLength === 0) return { ok: false, error: "The file is empty." };
  if (bytes.byteLength > MAX_UPLOAD_BYTES) return { ok: false, error: "The file is larger than 5 MB." };
  if (format === "csv") {
    const text = new TextDecoder("utf-8").decode(bytes);
    const table = toTable(null, parseCsv(text));
    return table.rows.length ? { ok: true, format, sheets: [table] } : { ok: false, error: "No rows were found under the header row." };
  }
  // An .xlsx is a zip; anything else (an old .xls, a renamed PDF) is refused up front.
  if (bytes[0] !== 0x50 || bytes[1] !== 0x4b) return { ok: false, error: "That isn't an .xlsx file. Save it as .xlsx or .csv and try again." };
  const wb = new ExcelJS.Workbook();
  try {
    await wb.xlsx.load(Buffer.from(bytes) as unknown as ArrayBuffer);
  } catch {
    return { ok: false, error: "The spreadsheet couldn't be read. Save it as .xlsx or .csv and try again." };
  }
  const sheets: SheetTable[] = [];
  for (const ws of wb.worksheets.slice(0, MAX_SHEETS)) {
    const raw: string[][] = [];
    ws.eachRow({ includeEmpty: true }, (row, rowNumber) => {
      if (rowNumber > MAX_ROWS + HEADER_SCAN_ROWS) return;
      const cells: string[] = [];
      row.eachCell({ includeEmpty: true }, (cell, col) => {
        if (col <= MAX_COLUMNS) cells[col - 1] = cellText(cell.value);
      });
      raw[rowNumber - 1] = Array.from(cells, (c) => c ?? "");
    });
    const table = toTable(ws.name, Array.from(raw, (r) => r ?? []));
    if (table.rows.length) sheets.push(table);
  }
  return sheets.length ? { ok: true, format, sheets } : { ok: false, error: "No rows were found in any sheet." };
}

// ---------------------------------------------------------------- questions

const HEADER_YES = /question|requirement|control( description)?|query|item|description|criteria/i;
const HEADER_NO = /^(#|no\.?|id|ref|reference|number|section|category|answer|response|comments?|notes?|evidence|status|yes\s*\/\s*no)$/i;

/** Pure: does this cell read like a question to answer, rather than a section heading or an id? */
export function looksLikeQuestion(text: string): boolean {
  const t = text.trim();
  if (!t) return false;
  if (t.endsWith("?")) return true;
  return t.split(/\s+/).length >= 4 && /[a-z]/i.test(t);
}

/**
 * Pure: which column holds the questions. `confident` is true when the
 * header names it or the cells clearly read as questions and no other column
 * comes close; the page asks the customer to confirm either way.
 */
export function detectQuestionColumn(table: Pick<SheetTable, "headers" | "rows">): { column: number; confident: boolean } {
  const { headers, rows } = table;
  if (!headers.length) return { column: 0, confident: false };
  const scores = headers.map((h, col) => {
    const cells = rows.map((r) => r[col] ?? "").filter((c) => c.trim() !== "");
    const questionMarks = cells.filter((c) => c.trim().endsWith("?")).length;
    const wordy = cells.filter(looksLikeQuestion).length;
    const avgLen = cells.length ? cells.reduce((n, c) => n + c.length, 0) / cells.length : 0;
    const header = HEADER_NO.test(h.trim()) ? -1 : HEADER_YES.test(h) ? 1 : 0;
    return { col, header, ratio: cells.length ? (questionMarks + wordy) / (2 * cells.length) : 0, score: questionMarks * 2 + wordy + Math.min(avgLen, 120) / 40 };
  });
  const named = scores.filter((s) => s.header === 1 && s.ratio > 0.3).sort((a, b) => b.score - a.score);
  if (named.length) return { column: named[0].col, confident: true };
  const ranked = scores.filter((s) => s.header !== -1).sort((a, b) => b.score - a.score);
  const best = ranked[0] ?? scores[0];
  const second = ranked[1];
  return { column: best.col, confident: best.ratio >= 0.5 && (!second || second.score < best.score / 2) };
}

/** Pure: the data rows that hold a question in `column`, by index. */
export function questionRows(rows: string[][], column: number): Array<{ rowIndex: number; question: string }> {
  return rows.flatMap((r, rowIndex) => {
    const q = (r[column] ?? "").trim();
    return looksLikeQuestion(q) ? [{ rowIndex, question: q }] : [];
  });
}

// ---------------------------------------------------------------- export

export type ExportAnswer = { rowIndex: number; answer: string; evidence: string; status: string };

/**
 * Pure: the original header and rows with Answer, Evidence and Status
 * appended. For CSV the appended cells are made formula-inert; an .xlsx
 * stores them as text, which never runs.
 */
export function exportRows(headers: string[], rows: string[][], answers: ExportAnswer[], disclaimer: string, format: SourceFormat): string[][] {
  const safe = format === "csv" ? neutraliseFormula : (v: string) => v;
  const byRow = new Map(answers.map((a) => [a.rowIndex, a]));
  const taken = new Set(headers.map((h) => h.trim().toLowerCase()));
  const name = (base: string) => (taken.has(base.toLowerCase()) ? `${base} (draft)` : base);
  const out: string[][] = [[...headers, name("Answer"), name("Evidence"), name("Status")]];
  rows.forEach((r, i) => {
    const a = byRow.get(i);
    out.push([...r, ...(a ? [a.answer, a.evidence, a.status].map(safe) : ["", "", ""])]);
  });
  out.push([]);
  out.push([disclaimer]);
  return out;
}

/** The export as an .xlsx workbook. Every cell is written as text, so nothing runs as a formula. */
export async function toXlsx(sheetName: string | null, rows: string[][]): Promise<Buffer> {
  const wb = new ExcelJS.Workbook();
  wb.creator = "Hebrides Cyber";
  const ws = wb.addWorksheet((sheetName || "Questionnaire").replace(/[\\/?*[\]:]/g, " ").slice(0, 31) || "Questionnaire");
  for (const r of rows) ws.addRow(r);
  const header = ws.getRow(1);
  header.font = { bold: true };
  const width = rows[0]?.length ?? 0;
  for (let c = width - 2; c <= width; c++) if (c >= 1) ws.getColumn(c).width = c === width ? 20 : 60;
  ws.views = [{ state: "frozen", ySplit: 1 }];
  return Buffer.from(await wb.xlsx.writeBuffer());
}

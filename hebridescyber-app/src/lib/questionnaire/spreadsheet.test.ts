// @vitest-environment node
import { describe, expect, it } from "vitest";
import ExcelJS from "exceljs";
import {
  cellText,
  decodeUpload,
  detectDelimiter,
  detectQuestionColumn,
  exportRows,
  formatFromName,
  looksLikeQuestion,
  neutraliseFormula,
  parseCsv,
  parseQuestionnaire,
  questionRows,
  toCsv,
  toTable,
  toXlsx,
  MAX_UPLOAD_BYTES,
} from "./spreadsheet";

const enc = (s: string) => new TextEncoder().encode(s);

describe("formatFromName", () => {
  it("knows .xlsx and .csv, case-insensitively, and nothing else", () => {
    expect(formatFromName("Supplier Q.XLSX")).toBe("xlsx");
    expect(formatFromName("q.csv")).toBe("csv");
    expect(formatFromName("q.xls")).toBeNull();
    expect(formatFromName("q.pdf")).toBeNull();
  });
});

describe("parseCsv", () => {
  it("handles quotes, escaped quotes, embedded newlines, CRLF and a BOM", () => {
    const rows = parseCsv('﻿ID,Question\r\n1,"Do you use MFA, everywhere?"\r\n2,"Say ""yes""\nor no"\r\n');
    expect(rows).toEqual([
      ["ID", "Question"],
      ["1", "Do you use MFA, everywhere?"],
      ["2", 'Say "yes"\nor no'],
    ]);
  });

  it("detects semicolon and tab delimiters", () => {
    expect(detectDelimiter("a;b;c\n1;2;3")).toBe(";");
    expect(detectDelimiter("a\tb\n1\t2")).toBe("\t");
    expect(detectDelimiter("just one")).toBe(",");
    expect(detectDelimiter('"a,b";c;d\n')).toBe(";");
    expect(parseCsv("Ref;Question\n1;Is data backed up?")).toEqual([["Ref", "Question"], ["1", "Is data backed up?"]]);
  });

  it("keeps a last row with no trailing newline", () => {
    expect(parseCsv("a,b\n1,2")).toEqual([["a", "b"], ["1", "2"]]);
  });
});

describe("toTable", () => {
  it("skips a title block above the header that names the question column", () => {
    const t = toTable("Sheet1", [["Acme supplier security questionnaire"], [], ["Ref", "Question", "Answer"], ["1", "Is MFA enforced?", ""], ["", "", ""]]);
    expect(t.headers).toEqual(["Ref", "Question", "Answer"]);
    expect(t.rows).toEqual([["1", "Is MFA enforced?", ""]]);
  });

  it("falls back to the first row with two filled cells, names blank headers and pads short rows", () => {
    const t = toTable(null, [["Title"], ["A", "", "C"], ["x"]]);
    expect(t.headers).toEqual(["A", "Column 2", "C"]);
    expect(t.rows).toEqual([["x", "", ""]]);
  });

  it("uses a single-cell row when nothing has two, and copes with an empty sheet", () => {
    expect(toTable(null, [["Only"], ["row"]]).headers).toEqual(["Only"]);
    expect(toTable(null, [])).toEqual({ name: null, headers: [], rows: [] });
  });
});

describe("cellText", () => {
  it("reads every exceljs value shape as text", () => {
    expect(cellText(null)).toBe("");
    expect(cellText("a")).toBe("a");
    expect(cellText(3)).toBe("3");
    expect(cellText(true)).toBe("true");
    expect(cellText(new Date("2026-11-01T10:00:00Z"))).toBe("2026-11-01");
    expect(cellText(new Date("nope"))).toBe("");
    expect(cellText({ richText: [{ text: "Is " }, { text: "MFA on?" }] })).toBe("Is MFA on?");
    expect(cellText({ text: "link", hyperlink: "https://x" })).toBe("link");
    expect(cellText({ formula: "A1", result: 4 })).toBe("4");
    expect(cellText({ error: "#REF!" })).toBe("");
    expect(cellText(Symbol.iterator)).toBe("");
  });
});

describe("question detection", () => {
  it("knows a question from a heading", () => {
    expect(looksLikeQuestion("MFA?")).toBe(true);
    expect(looksLikeQuestion("Describe your backup arrangements")).toBe(true);
    expect(looksLikeQuestion("Access control")).toBe(false);
    expect(looksLikeQuestion("1.2.3 4.5 6 7")).toBe(false);
    expect(looksLikeQuestion("  ")).toBe(false);
  });

  it("picks a column whose header names it", () => {
    const r = detectQuestionColumn({ headers: ["Ref", "Control question", "Response"], rows: [["1", "Do you enforce MFA?", "Yes"], ["2", "Are backups tested?", "No"]] });
    expect(r).toEqual({ column: 1, confident: true });
  });

  it("picks the wordy column when no header helps, confident only when it clearly leads", () => {
    const clear = detectQuestionColumn({ headers: ["A", "B"], rows: [["1", "Do you enforce MFA for all users?"], ["2", "Are backups kept offline?"]] });
    expect(clear).toEqual({ column: 1, confident: true });
    const unsure = detectQuestionColumn({ headers: ["A", "B"], rows: [["Do you patch?", "Are you sure it is done?"]] });
    expect(unsure.confident).toBe(false);
  });

  it("never picks an Answer column, and copes with no headers", () => {
    const r = detectQuestionColumn({ headers: ["Answer", "Item"], rows: [["Yes we always enforce MFA everywhere", "MFA?"]] });
    expect(r.column).toBe(1);
    expect(detectQuestionColumn({ headers: [], rows: [] })).toEqual({ column: 0, confident: false });
  });

  it("lists only rows that hold a question", () => {
    expect(questionRows([["Access control"], ["Is MFA enforced?"], [""], ["Describe how you patch servers"]], 0)).toEqual([
      { rowIndex: 1, question: "Is MFA enforced?" },
      { rowIndex: 3, question: "Describe how you patch servers" },
    ]);
  });
});

describe("decodeUpload", () => {
  it("decodes a data URL or bare base64", () => {
    const b64 = Buffer.from("a,b").toString("base64");
    const r = decodeUpload(`data:text/csv;base64,${b64}`);
    expect(r.ok && new TextDecoder().decode(r.bytes)).toBe("a,b");
    expect(decodeUpload(b64).ok).toBe(true);
    expect(decodeUpload("data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64," + b64).ok).toBe(true);
  });

  it("refuses junk, empty and oversized uploads", () => {
    expect(decodeUpload("data:text/csv;base64,@@@")).toEqual({ ok: false, error: expect.stringContaining("readable") });
    expect(decodeUpload("")).toEqual({ ok: false, error: "The file is empty." });
    const big = Buffer.alloc(MAX_UPLOAD_BYTES + 1).toString("base64");
    expect(decodeUpload(big)).toEqual({ ok: false, error: "The file is larger than 5 MB." });
  });
});

describe("parseQuestionnaire", () => {
  it("parses a CSV", async () => {
    const r = await parseQuestionnaire(enc("Ref,Question\n1,Is MFA enforced?\n"), "csv");
    expect(r).toEqual({ ok: true, format: "csv", sheets: [{ name: null, headers: ["Ref", "Question"], rows: [["1", "Is MFA enforced?"]] }] });
  });

  it("refuses an empty, oversized, header-only or non-xlsx file", async () => {
    expect(await parseQuestionnaire(new Uint8Array(), "csv")).toEqual({ ok: false, error: "The file is empty." });
    expect((await parseQuestionnaire(new Uint8Array(MAX_UPLOAD_BYTES + 1), "csv")).ok).toBe(false);
    expect(await parseQuestionnaire(enc("Ref,Question\n"), "csv")).toEqual({ ok: false, error: expect.stringContaining("No rows") });
    expect(await parseQuestionnaire(enc("%PDF-1.7"), "xlsx")).toEqual({ ok: false, error: expect.stringContaining("isn't an .xlsx") });
    expect(await parseQuestionnaire(new Uint8Array([0x50, 0x4b, 1, 2, 3]), "xlsx")).toEqual({ ok: false, error: expect.stringContaining("couldn't be read") });
  });

  it("parses every non-empty sheet of an .xlsx, rich text included", async () => {
    const wb = new ExcelJS.Workbook();
    const a = wb.addWorksheet("Security");
    a.addRow(["Supplier questionnaire"]);
    a.addRow(["Ref", "Question"]);
    a.addRow([1, { richText: [{ text: "Do you enforce " }, { text: "MFA?" }] }]);
    wb.addWorksheet("Empty");
    const c = wb.addWorksheet("Other");
    c.addRow(["ID", "Item"]);
    c.addRow(["x", "Are backups tested?"]);
    const bytes = new Uint8Array(await wb.xlsx.writeBuffer());
    const r = await parseQuestionnaire(bytes, "xlsx");
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.sheets.map((s) => s.name)).toEqual(["Security", "Other"]);
    expect(r.sheets[0].headers).toEqual(["Ref", "Question"]);
    expect(r.sheets[0].rows).toEqual([["1", "Do you enforce MFA?"]]);
  });

  it("refuses a workbook with no rows", async () => {
    const wb = new ExcelJS.Workbook();
    wb.addWorksheet("Empty");
    expect(await parseQuestionnaire(new Uint8Array(await wb.xlsx.writeBuffer()), "xlsx")).toEqual({ ok: false, error: "No rows were found in any sheet." });
  });
});

describe("export", () => {
  const headers = ["Ref", "Question", "Answer"];
  const rows = [["1", "Is MFA enforced?", ""], ["", "Section 2", ""]];
  const answers = [{ rowIndex: 0, answer: "=HYPERLINK(evil)", evidence: "Microsoft 365 check (2026-11-20): ok", status: "Accepted" }];

  it("appends Answer, Evidence and Status, renaming on a clash, and closes with the disclaimer", () => {
    const out = exportRows(headers, rows, answers, "Drafts, not certification.", "xlsx");
    expect(out[0]).toEqual(["Ref", "Question", "Answer", "Answer (draft)", "Evidence", "Status"]);
    expect(out[1]).toEqual(["1", "Is MFA enforced?", "", "=HYPERLINK(evil)", "Microsoft 365 check (2026-11-20): ok", "Accepted"]);
    expect(out[2]).toEqual(["", "Section 2", "", "", "", ""]);
    expect(out[out.length - 1]).toEqual(["Drafts, not certification."]);
  });

  it("makes appended cells formula-inert in CSV only", () => {
    expect(exportRows(headers, rows, answers, "d", "csv")[1][3]).toBe("'=HYPERLINK(evil)");
    expect(neutraliseFormula("+1")).toBe("'+1");
    expect(neutraliseFormula("Yes")).toBe("Yes");
  });

  it("writes CSV with a BOM, quoting and CRLF", () => {
    expect(toCsv([["a", 'say "hi", ok'], ["line\nbreak", "x"]])).toBe('﻿a,"say ""hi"", ok"\r\n"line\nbreak",x\r\n');
  });

  it("writes an .xlsx that reads back with a frozen bold header", async () => {
    const out = exportRows(headers, rows, answers, "d", "xlsx");
    const buf = await toXlsx("Sec/urity: Q", out);
    const wb = new ExcelJS.Workbook();
    await wb.xlsx.load(buf as unknown as ArrayBuffer);
    const ws = wb.worksheets[0];
    expect(ws.name).toBe("Sec urity  Q");
    expect(ws.getRow(2).getCell(4).value).toBe("=HYPERLINK(evil)");
    expect(ws.getRow(1).font?.bold).toBe(true);
    const fallback = await toXlsx(null, [["a"]]);
    const wb2 = new ExcelJS.Workbook();
    await wb2.xlsx.load(fallback as unknown as ArrayBuffer);
    expect(wb2.worksheets[0].name).toBe("Questionnaire");
  });
});

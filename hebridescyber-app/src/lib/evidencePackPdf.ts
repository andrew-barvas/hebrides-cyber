// The security evidence pack as a PDF, drawn with pdf-lib (pure JavaScript).
//
// Why not reportPdf.ts's htmlToPdf: that launches Playwright's headless
// Chromium, and the site's API routes run as Azure Static Web Apps managed
// Functions, built by Oryx with a plain `npm ci`. No Chromium binary (or the
// system libraries it needs) exists there, so `chromium.launch()` threw on
// every production request and the customer saw "The evidence pack could not
// be generated (500)". This renderer needs no browser, no file system and no
// font files: it uses the PDF standard fonts, which every PDF reader has.
//
// The standard fonts only encode Windows-1252 (WinAnsi), so text from
// findings and company names goes through toWinAnsi() (pdfText.ts) first; an unencodable
// character would otherwise make pdf-lib throw and turn a good pack into a 500.
import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage } from "pdf-lib";
import { colour, toWinAnsi } from "./pdfText";
import {
  EVIDENCE_PACK_FOOTER,
  SOURCE_COLOUR,
  SOURCE_LABEL,
  STATUS_COLOUR,
  STATUS_LABEL,
  declaredLabel,
  readinessLabel,
  type EvidencePack,
} from "./evidencePack";
import { REPORT_MUTED, REPORT_TEXT } from "./executiveReport";

export { toWinAnsi };

// A4 in points, with the HTML template's 18mm x 16mm margins.
const PAGE_W = 595.28;
const PAGE_H = 841.89;
const MARGIN_X = 45;
const MARGIN_TOP = 51;
const MARGIN_BOTTOM = 60;
const CONTENT_W = PAGE_W - MARGIN_X * 2;
const NAVY = "#0b3d5b";
const RULE = "#d5dde5";


type Style = { font: PDFFont; size: number; colour: string; indent?: number; lineGap?: number; after?: number };

/** Lays text out top to bottom across as many A4 pages as it needs. */
class Writer {
  private page: PDFPage;
  private y = PAGE_H - MARGIN_TOP;
  readonly pages: PDFPage[] = [];

  constructor(private readonly doc: PDFDocument) {
    this.page = this.addPage();
  }

  private addPage(): PDFPage {
    const page = this.doc.addPage([PAGE_W, PAGE_H]);
    this.pages.push(page);
    this.y = PAGE_H - MARGIN_TOP;
    return page;
  }

  /** Starts a new page unless `height` more points fit on this one. */
  ensure(height: number): void {
    if (this.y - height < MARGIN_BOTTOM) this.page = this.addPage();
  }

  space(points: number): void {
    this.y -= points;
  }

  /** Words of `text` wrapped to `width` points. A word wider than the line is broken. */
  private wrap(text: string, font: PDFFont, size: number, width: number): string[] {
    const lines: string[] = [];
    let line = "";
    for (const word of text.split(" ")) {
      if (!word) continue;
      const candidate = line ? `${line} ${word}` : word;
      if (font.widthOfTextAtSize(candidate, size) <= width) {
        line = candidate;
        continue;
      }
      if (line) lines.push(line);
      line = word;
      while (font.widthOfTextAtSize(line, size) > width && line.length > 1) {
        let cut = line.length - 1;
        while (cut > 1 && font.widthOfTextAtSize(line.slice(0, cut), size) > width) cut--;
        lines.push(line.slice(0, cut));
        line = line.slice(cut);
      }
    }
    if (line) lines.push(line);
    return lines;
  }

  /** A wrapped paragraph; `keep` points of what follows stay on the same page as its first line. */
  text(raw: string, style: Style, keep = 0): void {
    const indent = style.indent ?? 0;
    const lineHeight = style.size * 1.35 + (style.lineGap ?? 0);
    const lines = this.wrap(toWinAnsi(raw, style.font), style.font, style.size, CONTENT_W - indent);
    lines.forEach((line, i) => {
      this.ensure(lineHeight + (i === 0 ? keep : 0));
      this.y -= lineHeight;
      this.page.drawText(line, { x: MARGIN_X + indent, y: this.y + (lineHeight - style.size) / 2, size: style.size, font: style.font, color: colour(style.colour) });
    });
    this.y -= style.after ?? 0;
  }

  /** A short coloured label followed by bold text on the same line, then wrapped. */
  labelled(label: string, labelColour: string, rest: string, fonts: Fonts, indent: number): void {
    const size = 10;
    const tag = toWinAnsi(label.toUpperCase(), fonts.bold);
    const tagW = fonts.bold.widthOfTextAtSize(tag, 8) + 8;
    const lineHeight = size * 1.35;
    this.ensure(lineHeight);
    this.y -= lineHeight;
    this.page.drawRectangle({ x: MARGIN_X + indent, y: this.y + 1, width: tagW, height: 11, color: colour(labelColour) });
    this.page.drawText(tag, { x: MARGIN_X + indent + 4, y: this.y + 3.5, size: 8, font: fonts.bold, color: rgb(1, 1, 1) });
    const lines = this.wrap(toWinAnsi(rest, fonts.bold), fonts.bold, size, CONTENT_W - indent - tagW - 6);
    lines.forEach((line, i) => {
      if (i > 0) {
        this.ensure(lineHeight);
        this.y -= lineHeight;
      }
      this.page.drawText(line, { x: MARGIN_X + indent + tagW + 6, y: this.y + 2.5, size, font: fonts.bold, color: colour(REPORT_TEXT) });
    });
  }

  rule(thickness: number, hex: string, after: number): void {
    this.ensure(thickness + after);
    this.y -= thickness;
    this.page.drawRectangle({ x: MARGIN_X, y: this.y, width: CONTENT_W, height: thickness, color: colour(hex) });
    this.y -= after;
  }
}

type Fonts = { regular: PDFFont; bold: PDFFont };

/** Pure apart from pdf-lib: the evidence pack as PDF bytes. Same content as renderEvidencePackHtml. */
export async function renderEvidencePackPdf(pack: EvidencePack): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const date = pack.generatedAt.slice(0, 10);
  doc.setTitle(`Security evidence pack ${date}`);
  doc.setAuthor("Hebrides Cyber");
  doc.setCreator("Hebrides Cyber");
  doc.setProducer("Hebrides Cyber");
  doc.setCreationDate(new Date(pack.generatedAt));
  doc.setModificationDate(new Date(pack.generatedAt));
  const fonts: Fonts = { regular: await doc.embedFont(StandardFonts.Helvetica), bold: await doc.embedFont(StandardFonts.HelveticaBold) };
  const w = new Writer(doc);

  const body: Style = { font: fonts.regular, size: 10, colour: REPORT_TEXT, after: 4 };
  const muted: Style = { font: fonts.regular, size: 9.5, colour: REPORT_MUTED, after: 4 };
  const h2 = (title: string) => {
    w.space(14);
    w.text(title, { font: fonts.bold, size: 13, colour: NAVY, after: 3 }, 60);
    w.rule(0.75, RULE, 6);
  };
  const bullet = (text: string, style: Style, marker = "-") => w.text(`${marker} ${text}`, { ...style, indent: 12, after: 2 });

  // Heading
  w.text("Security evidence pack", { font: fonts.bold, size: 20, colour: NAVY, after: 4 });
  const sites = `${pack.sites.length} site${pack.sites.length === 1 ? "" : "s"} checked`;
  w.text(`${pack.company ? `${pack.company} · ` : ""}generated ${date} · ${sites}`, { ...muted, after: 8 });
  w.rule(2.5, NAVY, 10);
  w.text(
    "Evidence for a Cyber Essentials application, a cyber insurance proposal or a supplier questionnaire. Each answer says where it comes from: Evidenced (our checks saw it), Gap found (our checks saw a problem), Self-declared (your own answers in Hebrides Cyber) or Your records (something no outside check can see).",
    body,
  );

  h2("Sites checked");
  if (pack.sites.length) for (const s of pack.sites) bullet(`${s.host} (last scanned ${s.lastScanAt.slice(0, 10)})`, body);
  else w.text("No site has been scanned yet.", muted);

  h2("Insurance and supplier questionnaire answers");
  for (const a of pack.insurance) {
    w.text(a.question, { font: fonts.bold, size: 10, colour: REPORT_TEXT, after: 2 }, 30);
    w.labelled(SOURCE_LABEL[a.source], SOURCE_COLOUR[a.source], a.answer, fonts, 0);
    w.space(3);
    for (const d of a.detail) w.text(d, { ...muted, after: 1 });
    w.space(8);
  }

  h2(`Cyber Essentials readiness: ${readinessLabel(pack.ce.overall_status)}`);
  w.text(`${pack.ce.answered} of ${pack.ce.total_questions} self-assessment questions answered. ${pack.ce.recommendation}`, { ...muted, after: 8 });
  for (const c of pack.ce.controls) {
    w.text(`${c.control}: ${STATUS_LABEL[c.status] ?? c.status}`, { font: fonts.bold, size: 11, colour: STATUS_COLOUR[c.status] ?? REPORT_TEXT, after: 3 }, 30);
    for (const q of c.questions) bullet(`${q.prompt} — ${declaredLabel(q.answer)}`, body);
    if (c.gaps.length) w.text(`To address: ${c.gaps.slice(0, 5).join("; ")}`, { ...muted, indent: 12 });
    w.space(8);
  }

  const fix = pack.fixFirst.slice(0, 10);
  if (fix.length) {
    h2("Fix these first");
    fix.forEach((f, i) => bullet(`${f.title} (${f.host}, ${f.severity})`, body, `${i + 1}.`));
  }

  w.space(16);
  w.rule(0.75, RULE, 6);
  w.text(EVIDENCE_PACK_FOOTER, { ...muted, size: 8.5 });

  // Page numbers, now the count is known.
  w.pages.forEach((page, i) => {
    const label = `Security evidence pack ${date} · page ${i + 1} of ${w.pages.length}`;
    page.drawText(label, { x: MARGIN_X, y: MARGIN_BOTTOM / 2, size: 8, font: fonts.regular, color: colour(REPORT_MUTED) });
  });

  return doc.save();
}

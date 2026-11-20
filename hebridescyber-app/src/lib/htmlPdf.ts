// HTML report templates to PDF without a browser.
//
// reportPdf.ts's htmlToPdf prints with Playwright's headless Chromium, which
// the site's API routes cannot use: they run as Azure Static Web Apps managed
// Functions, built by Oryx with a plain `npm ci`, and no Chromium binary (or
// the system libraries it needs) exists there. Every PDF download from the
// site answered 500 until this replaced it (the evidence pack, #302, first).
// Scheduled reports still print with Chromium, in GitHub Actions, which
// installs it.
//
// This lays out the subset of HTML and CSS our own report templates use
// (executiveReport.ts, portfolioReport.ts, lookoutReportPdf.ts) and draws it
// with pdf-lib and the PDF standard fonts. The templates stay the one source
// of what a report says, so white-labelling, triage and wording rules carry
// over unchanged. It is not a general HTML engine:
//   - Elements: headings, p, div, span, b/strong, i/em, code, a, br, ul/ol/li,
//     table (thead/tbody/tr/th/td, colspan), figure/figcaption, img, inline svg
//     (line, polyline, circle, rect, text: the score-trend chart).
//   - CSS from the template's <style> block and style="" attributes, for
//     selectors made of tags, classes and descendants (rules with pseudo-classes,
//     attribute or sibling selectors are skipped). Properties: color,
//     background, font-size/-weight/-style/-family, text-transform, text-align,
//     line-height, margin, padding, border (-top/-bottom/-color), display
//     (none/block/inline/inline-block/flex/grid), width, min-width, max-width,
//     height, gap, flex-wrap, grid-template-columns: repeat(N, 1fr) and
//     page-break-inside: avoid.
//   - Images: JPEG/PNG data URIs, and https images (an Agency's logo) through
//     a fetch with a time and size cap. Anything else (SVG logos, WebP) is
//     left out rather than failing the report.
//   - Not drawn: rounded corners, link annotations, CSS beyond the above.
//     Text is restricted to WinAnsi (pdfText.ts).
import { PDFDocument, StandardFonts, type PDFFont, type PDFImage, type PDFPage } from "pdf-lib";
import { colour, toWinAnsi } from "./pdfText";

// ---------------------------------------------------------------------------
// Page geometry: A4 with the templates' `@page { margin: 18mm 16mm }`.
const PAGE_W = 595.28;
const PAGE_H = 841.89;
const MARGIN_Y = 18 * 2.8346;
const MARGIN_X = 16 * 2.8346;
const CONTENT_W = PAGE_W - MARGIN_X * 2;
const CONTENT_H = PAGE_H - MARGIN_Y * 2;
/** CSS px to PDF points: Chromium prints at 96 px per inch. */
const PX = 0.75;
const IMAGE_FETCH_TIMEOUT_MS = 5000;
const IMAGE_MAX_BYTES = 2 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Parsing

type El = { tag: string; attrs: Record<string, string>; children: Node[]; parent: El | null };
type Txt = { text: string; parent: El };
type Node = El | Txt;
const isEl = (n: Node): n is El => "tag" in n;

const VOID = new Set(["br", "img", "meta", "link", "hr", "input", "source", "wbr"]);
const RAW_TEXT = new Set(["style", "script", "title"]);
const ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
  rarr: "→",
  larr: "←",
  middot: "·",
  mdash: "—",
  ndash: "–",
  hellip: "…",
  copy: "©",
  pound: "£",
  euro: "€",
  rsquo: "’",
  lsquo: "‘",
  rdquo: "”",
  ldquo: "“",
  bull: "•",
  times: "×",
};

export function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (whole, name: string) => {
    if (name[0] === "#") {
      const cp = name[1] === "x" || name[1] === "X" ? Number.parseInt(name.slice(2), 16) : Number.parseInt(name.slice(1), 10);
      return Number.isFinite(cp) && cp > 0 && cp < 0x110000 ? String.fromCodePoint(cp) : "";
    }
    return ENTITIES[name.toLowerCase()] ?? whole;
  });
}

function parseAttrs(raw: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const re = /([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw))) attrs[m[1].toLowerCase()] = decodeEntities(m[2] ?? m[3] ?? m[4] ?? "");
  return attrs;
}

/** A tolerant parser for well-formed, self-generated HTML. */
export function parseHtml(html: string): El {
  const root: El = { tag: "#root", attrs: {}, children: [], parent: null };
  let cur = root;
  const lower = html.toLowerCase();
  const re = /<!--[\s\S]*?-->|<![^>]*>|<\/([a-zA-Z][a-zA-Z0-9]*)\s*>|<([a-zA-Z][a-zA-Z0-9]*)((?:\s+[^\s=>/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*(\/?)>/g;
  let last = 0;
  let m: RegExpExecArray | null;
  const addText = (raw: string) => {
    if (raw) cur.children.push({ text: decodeEntities(raw), parent: cur });
  };
  while ((m = re.exec(html))) {
    addText(html.slice(last, m.index));
    last = re.lastIndex;
    if (m[1]) {
      const tag = m[1].toLowerCase();
      let n: El | null = cur;
      while (n && n.tag !== tag) n = n.parent;
      if (n?.parent) cur = n.parent;
    } else if (m[2]) {
      const tag = m[2].toLowerCase();
      const el: El = { tag, attrs: parseAttrs(m[3] ?? ""), children: [], parent: cur };
      cur.children.push(el);
      if (RAW_TEXT.has(tag) && !m[4]) {
        const end = lower.indexOf(`</${tag}`, last);
        const stop = end < 0 ? html.length : end;
        const raw = html.slice(last, stop);
        el.children.push({ text: tag === "title" ? decodeEntities(raw) : raw, parent: el });
        last = end < 0 ? html.length : html.indexOf(">", end) + 1;
        re.lastIndex = last;
      } else if (!m[4] && !VOID.has(tag)) {
        cur = el;
      }
    }
  }
  addText(html.slice(last));
  return root;
}

function find(el: El, tag: string): El | null {
  for (const c of el.children) {
    if (!isEl(c)) continue;
    if (c.tag === tag) return c;
    const hit = find(c, tag);
    if (hit) return hit;
  }
  return null;
}

function textContent(n: Node): string {
  return isEl(n) ? n.children.map(textContent).join("") : n.text;
}

// ---------------------------------------------------------------------------
// CSS

type Compound = { tag?: string; classes: string[] };
type Rule = { chain: Compound[]; spec: number; order: number; decls: Record<string, string> };

function parseDecls(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of text.split(";")) {
    const i = part.indexOf(":");
    if (i < 0) continue;
    const prop = part.slice(0, i).trim().toLowerCase();
    const value = part.slice(i + 1).trim();
    if (prop && value) out[prop] = value;
  }
  return out;
}

export function parseCss(css: string): Rule[] {
  const rules: Rule[] = [];
  const clean = css.replace(/\/\*[\s\S]*?\*\//g, "");
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let m: RegExpExecArray | null;
  let order = 0;
  while ((m = re.exec(clean))) {
    const decls = parseDecls(m[2]);
    for (const raw of m[1].split(",")) {
      const sel = raw.trim();
      if (!sel || sel.startsWith("@") || /[:[*+~]/.test(sel)) continue;
      const chain: Compound[] = [];
      let ok = true;
      for (const part of sel.replace(/>/g, " ").split(/\s+/).filter(Boolean)) {
        const pm = /^([a-z][a-z0-9]*)?((?:\.[\w-]+)*)$/i.exec(part);
        if (!pm || (!pm[1] && !pm[2])) {
          ok = false;
          break;
        }
        chain.push({ tag: pm[1]?.toLowerCase(), classes: pm[2] ? pm[2].slice(1).split(".") : [] });
      }
      if (!ok || chain.length === 0) continue;
      const spec = chain.reduce((s, c) => s + c.classes.length * 10 + (c.tag ? 1 : 0), 0);
      rules.push({ chain, spec, order: order++, decls });
    }
  }
  return rules.sort((a, b) => a.spec - b.spec || a.order - b.order);
}

const classesOf = (el: El) => (el.attrs.class ?? "").split(/\s+/).filter(Boolean);

function compoundMatches(el: El, c: Compound): boolean {
  if (c.tag && c.tag !== el.tag) return false;
  if (c.classes.length === 0) return true;
  const own = classesOf(el);
  return c.classes.every((k) => own.includes(k));
}

function ruleMatches(el: El, chain: Compound[]): boolean {
  if (!compoundMatches(el, chain[chain.length - 1])) return false;
  let i = chain.length - 2;
  let anc = el.parent;
  while (i >= 0 && anc) {
    if (compoundMatches(anc, chain[i])) i--;
    anc = anc.parent;
  }
  return i < 0;
}

// Browser defaults for the elements the templates use (Chromium's UA sheet, trimmed).
const UA: Record<string, Record<string, string>> = {
  body: { "font-size": "16px", color: "#000000", "line-height": "1.2" },
  h1: { display: "block", "font-size": "2em", "font-weight": "bold", margin: "0.67em 0" },
  h2: { display: "block", "font-size": "1.5em", "font-weight": "bold", margin: "0.83em 0" },
  h3: { display: "block", "font-size": "1.17em", "font-weight": "bold", margin: "1em 0" },
  h4: { display: "block", "font-weight": "bold", margin: "1.33em 0" },
  p: { display: "block", margin: "1em 0" },
  ul: { display: "block", margin: "1em 0", "padding-left": "40px" },
  ol: { display: "block", margin: "1em 0", "padding-left": "40px" },
  li: { display: "list-item" },
  div: { display: "block" },
  table: { display: "table" },
  figure: { display: "block", margin: "1em 40px" },
  figcaption: { display: "block" },
  b: { "font-weight": "bold" },
  strong: { "font-weight": "bold" },
  th: { "font-weight": "bold", "text-align": "center", padding: "1px" },
  td: { padding: "1px" },
  i: { "font-style": "italic" },
  em: { "font-style": "italic" },
  code: { "font-family": "monospace" },
  svg: { display: "block" },
  head: { display: "none" },
  style: { display: "none" },
  script: { display: "none" },
  title: { display: "none" },
};
/** Properties a child takes from its parent when it doesn't set them. */
type Inherited = "color" | "font-size" | "font-weight" | "font-style" | "font-family" | "text-transform" | "text-align" | "line-height";

type Box4 = [number, number, number, number]; // top right bottom left
type Border = { w: number; c: string } | null;
export type Computed = {
  display: string;
  color: string;
  size: number;
  bold: boolean;
  italic: boolean;
  mono: boolean;
  upper: boolean;
  align: "left" | "center" | "right";
  lineHeight: number;
  bg: string | null;
  margin: Box4;
  padding: Box4;
  borderTop: Border;
  borderBottom: Border;
  borderSides: Border;
  width: number | null;
  widthPct: number | null;
  minWidth: number | null;
  maxWidth: number | null;
  height: number | null;
  gap: number;
  gridCols: number;
  wrap: boolean;
  avoid: boolean;
};

const HEX = /#[0-9a-f]{3,8}\b/i;
const NAMED: Record<string, string> = { white: "#ffffff", black: "#000000", red: "#ff0000", transparent: "" };

function parseColour(value: string | undefined): string | null {
  if (!value) return null;
  const hex = HEX.exec(value)?.[0];
  if (hex) {
    if (hex.length === 4) return `#${hex[1]}${hex[1]}${hex[2]}${hex[2]}${hex[3]}${hex[3]}`;
    return hex.slice(0, 7);
  }
  const rgbm = /rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/i.exec(value);
  if (rgbm) return `#${[rgbm[1], rgbm[2], rgbm[3]].map((n) => Number(n).toString(16).padStart(2, "0")).join("")}`;
  const word = value.trim().toLowerCase();
  return word in NAMED ? NAMED[word] || null : null;
}

/** A CSS length in points; `em` against `em`, percentages give null. */
function length(value: string | undefined, em: number): number | null {
  if (!value) return null;
  const m = /^(-?[\d.]+)(px|em|rem|mm|pt|%)?$/i.exec(value.trim());
  if (!m) return null;
  const n = Number(m[1]);
  switch ((m[2] ?? "").toLowerCase()) {
    case "px":
      return n * PX;
    case "em":
      return n * em;
    case "rem":
      return n * 12;
    case "mm":
      return n * 2.8346;
    case "pt":
      return n;
    case "%":
      return null;
    default:
      return n === 0 ? 0 : null;
  }
}

function box4(value: string | undefined, em: number): Box4 | null {
  if (!value) return null;
  const parts = value.trim().split(/\s+/).map((v) => (v === "auto" ? 0 : length(v, em) ?? 0));
  const [t, r = t, b = t, l = r] = parts;
  return [t, r, b, l];
}

function border(value: string | undefined, colourOverride: string | null): Border {
  if (!value || /\bnone\b/.test(value)) return null;
  const w = /([\d.]+)px/.exec(value);
  const width = w ? Number(w[1]) * PX : 0.75;
  const c = colourOverride ?? parseColour(value) ?? "#000000";
  return width > 0 ? { w: width, c } : null;
}

class Styler {
  private cache = new Map<El, Computed>();
  constructor(private readonly rules: Rule[]) {}

  get(el: El): Computed {
    const hit = this.cache.get(el);
    if (hit) return hit;
    const parent = el.parent && el.parent.tag !== "#root" ? this.get(el.parent) : null;
    const decls: Record<string, string> = { ...(UA[el.tag] ?? { display: "inline" }) };
    for (const r of this.rules) if (ruleMatches(el, r.chain)) Object.assign(decls, r.decls);
    if (el.attrs.style) Object.assign(decls, parseDecls(el.attrs.style));
    expandShorthands(decls);

    const inherit = (prop: Inherited) => decls[prop] === undefined || decls[prop] === "inherit";
    const parentSize = parent?.size ?? 12;
    let size = parentSize;
    if (!inherit("font-size")) size = length(decls["font-size"], parentSize) ?? parentSize;
    const weight = inherit("font-weight") ? null : decls["font-weight"];
    const lh = decls["line-height"];
    const c: Computed = {
      display: decls.display ?? "inline",
      color: (inherit("color") ? null : parseColour(decls.color)) ?? parent?.color ?? "#000000",
      size,
      bold: weight ? weight === "bold" || weight === "bolder" || Number(weight) >= 600 : parent?.bold ?? false,
      italic: inherit("font-style") ? parent?.italic ?? false : decls["font-style"] === "italic",
      mono: inherit("font-family") ? parent?.mono ?? false : /mono|courier/i.test(decls["font-family"] ?? ""),
      upper: inherit("text-transform") ? parent?.upper ?? false : decls["text-transform"] === "uppercase",
      align: inherit("text-align") ? parent?.align ?? "left" : ((["center", "right"].includes(decls["text-align"]) ? decls["text-align"] : "left") as Computed["align"]),
      lineHeight: lh && lh !== "inherit" ? (/^[\d.]+$/.test(lh) ? Number(lh) : (length(lh, size) ?? size * 1.2) / size) : parent?.lineHeight ?? 1.2,
      bg: parseColour(decls.background ?? decls["background-color"]),
      margin: box4(decls.margin, size) ?? [0, 0, 0, 0],
      padding: box4(decls.padding, size) ?? [0, 0, 0, 0],
      borderTop: null,
      borderBottom: null,
      borderSides: null,
      width: length(decls.width, size),
      widthPct: /^[\d.]+%$/.test(decls.width ?? "") ? Number.parseFloat(decls.width) : null,
      minWidth: length(decls["min-width"], size),
      maxWidth: length(decls["max-width"], size),
      height: length(decls.height, size),
      gap: length(decls.gap, size) ?? 0,
      gridCols: Number(/repeat\(\s*(\d+)/.exec(decls["grid-template-columns"] ?? "")?.[1] ?? 0),
      wrap: decls["flex-wrap"] === "wrap",
      avoid: decls["page-break-inside"] === "avoid" || decls["break-inside"] === "avoid",
    };
    for (const [i, side] of (["top", "right", "bottom", "left"] as const).entries()) {
      const v = length(decls[`margin-${side}`], size);
      if (v !== null) c.margin[i] = v;
      const p = length(decls[`padding-${side}`], size);
      if (p !== null) c.padding[i] = p;
    }
    const borderColour = parseColour(decls["border-color"]);
    c.borderSides = border(decls.border, borderColour);
    c.borderTop = border(decls["border-top"], borderColour) ?? c.borderSides;
    c.borderBottom = border(decls["border-bottom"], borderColour) ?? c.borderSides;
    this.cache.set(el, c);
    return c;
  }
}

function expandShorthands(decls: Record<string, string>): void {
  const font = decls.font;
  if (font) {
    if (/\bbold\b/.test(font)) decls["font-weight"] = "bold";
    const size = /([\d.]+(?:px|em|pt))/.exec(font);
    if (size) decls["font-size"] = size[1];
  }
}

// ---------------------------------------------------------------------------
// Layout

type Fonts = { regular: PDFFont; bold: PDFFont; italic: PDFFont; boldItalic: PDFFont; mono: PDFFont };
type Images = Map<string, PDFImage>;
/** Per render: two downloads can interleave across the image fetch, so nothing lives at module level. */
type Ctx = { styler: Styler; fonts: Fonts; images: Images; lists: number[] };

/** One vertical slice of the document: pagination moves whole items. */
type Item = {
  h: number;
  draw: (page: PDFPage, x: number, top: number) => void;
  keepWithNext?: boolean;
  spacer?: boolean;
  /** A table's header row, drawn again when the table continues on a new page. */
  header?: Item;
};

/** An unbreakable block of known size, drawn at any height at least its own (flex and table stretching). */
type Box = { w: number; h: number; draw: (page: PDFPage, x: number, top: number, h: number) => void };

function fontFor(s: Computed, f: Fonts): PDFFont {
  if (s.mono) return f.mono;
  if (s.bold && s.italic) return f.boldItalic;
  if (s.bold) return f.bold;
  if (s.italic) return f.italic;
  return f.regular;
}

const spacer = (h: number): Item => ({ h, spacer: true, draw: () => {} });

function stack(items: Item[]): Item {
  const h = items.reduce((s, i) => s + i.h, 0);
  return {
    h,
    draw: (page, x, top) => {
      let y = top;
      for (const it of items) {
        it.draw(page, x, y);
        y -= it.h;
      }
    },
  };
}

function rect(page: PDFPage, x: number, top: number, w: number, h: number, bg: string | null, side: Border): void {
  if (w <= 0 || h <= 0) return;
  if (bg) page.drawRectangle({ x, y: top - h, width: w, height: h, color: colour(bg) });
  if (side) page.drawRectangle({ x, y: top - h, width: w, height: h, borderColor: colour(side.c), borderWidth: side.w });
}

function hRule(page: PDFPage, x: number, y: number, w: number, b: NonNullable<Border>): void {
  page.drawRectangle({ x, y: y - b.w, width: w, height: b.w, color: colour(b.c) });
}

// --- inline formatting -------------------------------------------------------

type Token =
  | { kind: "word"; text: string; w: number; s: Computed; font: PDFFont }
  | { kind: "space"; w: number }
  | { kind: "box"; box: Box; s: Computed }
  | { kind: "break" };

function isInline(el: El, ctx: Ctx): boolean {
  const d = ctx.styler.get(el).display;
  return d === "inline" || d === "inline-block";
}

function textTokens(text: string, s: Computed, ctx: Ctx, out: Token[]): void {
  const font = fontFor(s, ctx.fonts);
  const shown = s.upper ? text.toUpperCase() : text;
  for (const piece of shown.split(/(\s+)/)) {
    if (!piece) continue;
    if (/^\s+$/.test(piece)) {
      if (piece.includes(" ") && !/[ \t\n\r]/.test(piece)) {
        out.push({ kind: "space", w: font.widthOfTextAtSize(" ", s.size) * piece.length });
      } else {
        out.push({ kind: "space", w: font.widthOfTextAtSize(" ", s.size) });
      }
      continue;
    }
    const safe = toWinAnsi(piece, font);
    if (safe) out.push({ kind: "word", text: safe, w: font.widthOfTextAtSize(safe, s.size), s, font });
  }
}

/** Inline content of one element, flattened to tokens. */
function inlineTokens(node: Node, ctx: Ctx, out: Token[], avail: number): void {
  if (!isEl(node)) {
    textTokens(node.text, ctx.styler.get(node.parent), ctx, out);
    return;
  }
  const s = ctx.styler.get(node);
  if (s.display === "none") return;
  if (node.tag === "br") {
    out.push({ kind: "break" });
    return;
  }
  if (node.tag === "img") {
    const box = imageBox(node, s, ctx, avail);
    if (box) out.push({ kind: "box", box, s });
    return;
  }
  if (node.tag === "svg") {
    out.push({ kind: "box", box: svgBox(node, avail, ctx), s });
    return;
  }
  // A decorated inline element (severity badge, attack-chain node) is one unbreakable box.
  if (s.bg || s.borderSides || s.display === "inline-block") {
    const inner: Token[] = [];
    for (const c of node.children) inlineTokens(c, ctx, inner, avail);
    const words = trimSpaces(inner);
    const textW = words.reduce((w, t) => w + (t.kind === "word" || t.kind === "space" ? t.w : t.kind === "box" ? t.box.w : 0), 0);
    const [pt, pr, pb, pl] = s.padding;
    const bw = s.borderSides?.w ?? 0;
    const lineH = Math.max(s.size, ...words.map((t) => (t.kind === "word" ? t.s.size : t.kind === "box" ? t.box.h : 0))) * 1.15;
    const box: Box = {
      w: textW + pl + pr + bw * 2,
      h: lineH + pt + pb + bw * 2,
      draw: (page, x, top, h) => {
        rect(page, x, top, textW + pl + pr + bw * 2, h, s.bg, s.borderSides);
        let cx = x + bw + pl;
        const base = top - bw - pt - lineH / 2 - s.size * 0.33;
        words.forEach((t, i) => {
          if (t.kind === "word") {
            page.drawText(withSpace(t, words[i + 1]), { x: cx, y: base, size: t.s.size, font: t.font, color: colour(t.s.color) });
            cx += t.w;
          } else if (t.kind === "space") cx += t.w;
          else if (t.kind === "box") {
            t.box.draw(page, cx, top - bw - pt, t.box.h);
            cx += t.box.w;
          }
        });
      },
    };
    out.push({ kind: "box", box, s });
    return;
  }
  const gapW = s.wrap && s.gap ? s.gap : 0;
  node.children.forEach((c, i) => {
    if (gapW && i > 0 && isEl(c)) out.push({ kind: "space", w: gapW });
    inlineTokens(c, ctx, out, avail);
  });
}

/** A word followed by a space is drawn with it, so copied or extracted text keeps its spaces (layout still positions each word). */
function withSpace(t: Extract<Token, { kind: "word" }>, next: Token | undefined): string {
  return next?.kind === "space" ? `${t.text} ` : t.text;
}

function trimSpaces(tokens: Token[]): Token[] {
  let a = 0;
  let b = tokens.length;
  while (a < b && tokens[a].kind === "space") a++;
  while (b > a && tokens[b - 1].kind === "space") b--;
  return tokens.slice(a, b);
}

/** Splits a word wider than the line into pieces that fit. */
function splitWord(t: Extract<Token, { kind: "word" }>, width: number): Token[] {
  const out: Token[] = [];
  let rest = t.text;
  while (rest) {
    let n = rest.length;
    while (n > 1 && t.font.widthOfTextAtSize(rest.slice(0, n), t.s.size) > width) n--;
    const piece = rest.slice(0, n);
    out.push({ ...t, text: piece, w: t.font.widthOfTextAtSize(piece, t.s.size) });
    rest = rest.slice(n);
  }
  return out;
}

/** Lines of inline tokens, wrapped to `width`, as items. */
function lineItems(tokens: Token[], block: Computed, width: number): Item[] {
  const lines: Token[][] = [];
  let line: Token[] = [];
  let used = 0;
  const flush = () => {
    lines.push(trimSpaces(line));
    line = [];
    used = 0;
  };
  const queue = [...tokens];
  while (queue.length) {
    const t = queue.shift() as Token;
    if (t.kind === "break") {
      flush();
      continue;
    }
    if (t.kind === "space") {
      if (line.length && line[line.length - 1].kind !== "space") {
        line.push(t);
        used += t.w;
      }
      continue;
    }
    const w = t.kind === "word" ? t.w : t.box.w;
    if (used + w > width + 0.01 && line.some((x) => x.kind !== "space")) {
      flush();
    }
    if (t.kind === "word" && t.w > width) {
      const parts = splitWord(t, width);
      queue.unshift(...parts.slice(1).flatMap((p) => [{ kind: "break" } as Token, p]));
      line.push(parts[0]);
      used += (parts[0] as { w: number }).w;
      continue;
    }
    line.push(t);
    used += w;
  }
  if (line.length) flush();

  return lines
    .filter((l, i) => l.length > 0 || i < lines.length - 1)
    .map((l) => {
      const textH = Math.max(block.size, ...l.map((t) => (t.kind === "word" ? t.s.size : 0))) * block.lineHeight;
      const boxH = Math.max(0, ...l.map((t) => (t.kind === "box" ? t.box.h : 0)));
      const h = l.length ? Math.max(textH, boxH + 2) : block.size * block.lineHeight;
      const lineW = l.reduce((s, t) => s + (t.kind === "word" || t.kind === "space" ? t.w : t.kind === "box" ? t.box.w : 0), 0);
      return {
        h,
        draw: (page: PDFPage, x: number, top: number) => {
          let cx = x + (block.align === "center" ? (width - lineW) / 2 : block.align === "right" ? width - lineW : 0);
          const mid = top - h / 2;
          l.forEach((t, i) => {
            if (t.kind === "word") {
              page.drawText(withSpace(t, l[i + 1]), { x: cx, y: mid - t.s.size * 0.33, size: t.s.size, font: t.font, color: colour(t.s.color) });
              cx += t.w;
            } else if (t.kind === "space") cx += t.w;
            else if (t.kind === "box") {
              t.box.draw(page, cx, mid + t.box.h / 2, t.box.h);
              cx += t.box.w;
            }
          });
        },
      };
    });
}

// --- images and svg ------------------------------------------------------------

function imageBox(el: El, s: Computed, ctx: Ctx, avail: number): Box | null {
  const img = ctx.images.get(el.attrs.src ?? "");
  if (!img) return null;
  let w = img.width * PX;
  let h = img.height * PX;
  const ratio = h / w;
  if (s.widthPct) {
    w = (avail * s.widthPct) / 100;
    h = w * ratio;
  } else if (s.height) {
    h = s.height;
    w = h / ratio;
  } else if (s.width) {
    w = s.width;
    h = w * ratio;
  }
  if (s.maxWidth && w > s.maxWidth) {
    w = s.maxWidth;
    h = w * ratio;
  }
  if (w > avail) {
    w = avail;
    h = w * ratio;
  }
  const side = s.borderSides;
  return {
    w,
    h,
    draw: (page, x, top) => {
      page.drawImage(img, { x, y: top - h, width: w, height: h });
      if (side) rect(page, x, top, w, h, null, side);
    },
  };
}

function svgBox(el: El, avail: number, ctx: Ctx): Box {
  const vb = (el.attrs.viewbox ?? "").split(/[\s,]+/).map(Number);
  const vw = Number(el.attrs.width) || vb[2] || 300;
  const vh = Number(el.attrs.height) || vb[3] || 150;
  const scale = Math.min(PX, avail / vw);
  const w = vw * scale;
  const h = vh * scale;
  const shapes = el.children.filter(isEl);
  return {
    w,
    h,
    draw: (page, x, top) => {
      const px = (v: string | undefined) => x + (Number(v) || 0) * scale;
      const py = (v: string | undefined) => top - (Number(v) || 0) * scale;
      const strokeOf = (s: El) => parseColour(s.attrs.stroke);
      for (const s of shapes) {
        const sw = (Number(s.attrs["stroke-width"]) || 1) * scale;
        if (s.tag === "line" && strokeOf(s)) {
          page.drawLine({ start: { x: px(s.attrs.x1), y: py(s.attrs.y1) }, end: { x: px(s.attrs.x2), y: py(s.attrs.y2) }, thickness: sw, color: colour(strokeOf(s) as string) });
        } else if (s.tag === "polyline" && strokeOf(s)) {
          const pts = (s.attrs.points ?? "").trim().split(/\s+/).map((p) => p.split(",").map(Number));
          for (let i = 1; i < pts.length; i++) {
            page.drawLine({ start: { x: x + pts[i - 1][0] * scale, y: top - pts[i - 1][1] * scale }, end: { x: x + pts[i][0] * scale, y: top - pts[i][1] * scale }, thickness: sw, color: colour(strokeOf(s) as string) });
          }
        } else if (s.tag === "circle") {
          const fill = parseColour(s.attrs.fill);
          if (fill) page.drawCircle({ x: px(s.attrs.cx), y: py(s.attrs.cy), size: (Number(s.attrs.r) || 1) * scale, color: colour(fill) });
        } else if (s.tag === "rect") {
          const fill = parseColour(s.attrs.fill);
          const rw = (Number(s.attrs.width) || 0) * scale;
          const rh = (Number(s.attrs.height) || 0) * scale;
          if (fill) page.drawRectangle({ x: px(s.attrs.x), y: py(s.attrs.y) - rh, width: rw, height: rh, color: colour(fill) });
        } else if (s.tag === "text") {
          const font = ctx.fonts.regular;
          const size = (Number(s.attrs["font-size"]) || 10) * scale;
          const text = toWinAnsi(textContent(s), font);
          const tw = font.widthOfTextAtSize(text, size);
          const anchor = s.attrs["text-anchor"];
          const tx = px(s.attrs.x) - (anchor === "end" ? tw : anchor === "middle" ? tw / 2 : 0);
          page.drawText(text, { x: tx, y: py(s.attrs.y), size, font, color: colour(parseColour(s.attrs.fill) ?? "#000000") });
        }
      }
    },
  };
}

// --- blocks ------------------------------------------------------------------

/** An element laid out as one unbreakable box `width` wide. */
function layoutBox(el: El, width: number, ctx: Ctx): Box {
  const s = ctx.styler.get(el);
  const [pt, pr, pb, pl] = s.padding;
  const bw = s.borderSides?.w ?? 0;
  const inner = Math.max(1, width - pl - pr - bw * 2);
  // A flex row or grid inside a flex item or cell (the severity chips) keeps its own layout.
  const items = s.display === "flex" && !s.wrap ? [flexRow(el, inner, ctx)] : s.display === "grid" && s.gridCols > 0 ? gridRows(el, inner, ctx) : contentItems(el, inner, ctx);
  const contentH = items.reduce((h, i) => h + i.h, 0);
  const bottomRule = !s.borderSides && s.borderBottom ? s.borderBottom : null;
  const topRule = !s.borderSides && s.borderTop ? s.borderTop : null;
  const h = contentH + pt + pb + bw * 2 + (bottomRule?.w ?? 0) + (topRule?.w ?? 0);
  return {
    w: width,
    h,
    draw: (page, x, top, hh) => {
      rect(page, x, top, width, hh, s.bg, s.borderSides);
      if (topRule) hRule(page, x, top, width, topRule);
      let y = top - bw - pt - (topRule?.w ?? 0);
      for (const it of items) {
        it.draw(page, x + bw + pl, y);
        y -= it.h;
      }
      if (bottomRule) hRule(page, x, top - hh + bottomRule.w, width, bottomRule);
    },
  };
}

const boxItem = (b: Box): Item => ({ h: b.h, draw: (page, x, top) => b.draw(page, x, top, b.h) });

/** The children of `el`, laid out in `width`: runs of inline content become lines, blocks recurse. */
function contentItems(el: El, width: number, ctx: Ctx): Item[] {
  const s = ctx.styler.get(el);
  const items: Item[] = [];
  let run: Node[] = [];
  const flushRun = () => {
    if (!run.length) return;
    const tokens: Token[] = [];
    for (const n of run) inlineTokens(n, ctx, tokens, width);
    run = [];
    if (tokens.some((t) => t.kind !== "space")) items.push(...lineItems(tokens, s, width));
  };
  const gapW = s.wrap && s.gap ? s.gap : 0;
  el.children.forEach((c, i) => {
    if (!isEl(c) || isInline(c, ctx) || c.tag === "br" || c.tag === "img") {
      if (gapW && i > 0 && isEl(c)) run.push({ text: " ", parent: el });
      run.push(c);
      return;
    }
    flushRun();
    items.push(...blockItems(c, width, ctx, s));
  });
  flushRun();
  return items;
}

/** A block-level element as pageable items, margins included. */
function blockItems(el: El, width: number, ctx: Ctx, parentStyle: Computed | null): Item[] {
  const s = ctx.styler.get(el);
  if (s.display === "none") return [];
  const [mt, mr, mb, ml] = s.margin;
  const avail = Math.max(1, width - ml - mr);
  let body: Item[];
  const isList = el.tag === "ol" || el.tag === "ul";
  if (isList) ctx.lists.push(0);

  if (el.tag === "table" || s.display === "table") body = tableItems(el, avail, ctx);
  else if (el.tag === "svg") body = [boxItem(svgBox(el, avail, ctx))];
  else if (s.display === "flex" && !s.wrap) body = [flexRow(el, avail, ctx)];
  else if (s.display === "grid" && s.gridCols > 0) body = gridRows(el, avail, ctx);
  else if (s.bg || s.borderSides) {
    const b = layoutBox(el, avail, ctx);
    body = b.h <= CONTENT_H ? [boxItem(b)] : plainItems(el, avail, ctx);
  } else body = plainItems(el, avail, ctx);

  if (isList) ctx.lists.pop();
  if (s.display === "list-item" && body.length) {
    const ordered = parentStyle && el.parent?.tag === "ol";
    const n = ordered && ctx.lists.length ? ++ctx.lists[ctx.lists.length - 1] : 0;
    const marker = ordered ? `${n}.` : "•";
    const font = fontFor(s, ctx.fonts);
    const first = body[0];
    const mw = font.widthOfTextAtSize(marker, s.size);
    const lineH = s.size * s.lineHeight;
    body[0] = {
      ...first,
      draw: (page, x, top) => {
        page.drawText(marker, { x: x - mw - 4, y: top - lineH / 2 - s.size * 0.33, size: s.size, font, color: colour(s.color) });
        first.draw(page, x, top);
      },
    };
  }

  if (s.avoid) {
    const total = body.reduce((h, i) => h + i.h, 0);
    if (total <= CONTENT_H) body = [stack(body)];
  }
  if (/^h[1-6]$/.test(el.tag) && body.length) body[body.length - 1] = { ...body[body.length - 1], keepWithNext: true };

  const shifted = ml ? body.map((it) => ({ ...it, draw: (page: PDFPage, x: number, top: number) => it.draw(page, x + ml, top) })) : body;
  return [...(mt ? [spacer(mt)] : []), ...shifted, ...(mb ? [spacer(mb)] : [])];
}

/** A plain block: its own padding and top/bottom rules around its content. */
function plainItems(el: El, width: number, ctx: Ctx): Item[] {
  const s = ctx.styler.get(el);
  const [pt, pr, pb, pl] = s.padding;
  const inner = contentItems(el, Math.max(1, width - pl - pr), ctx).map((it) =>
    pl ? { ...it, draw: (page: PDFPage, x: number, top: number) => it.draw(page, x + pl, top) } : it,
  );
  const out: Item[] = [];
  if (s.borderTop) {
    const b = s.borderTop;
    out.push({ h: b.w, draw: (page, x, top) => hRule(page, x, top, width, b) });
  }
  if (pt) out.push(spacer(pt));
  out.push(...inner);
  if (pb) out.push(spacer(pb));
  if (s.borderBottom) {
    const b = s.borderBottom;
    const rule: Item = { h: b.w, draw: (page, x, top) => hRule(page, x, top, width, b) };
    // Keep a heading's underline with the heading.
    if (out.length && /^h[1-6]$/.test(el.tag)) {
      const last = out.pop() as Item;
      out.push(stack([last, rule]));
    } else out.push(rule);
  }
  return out;
}

/** Natural widths of a flex or table child: [narrowest, widest] in points. */
function intrinsic(el: El, ctx: Ctx): [number, number] {
  const s = ctx.styler.get(el);
  if (el.tag === "img") {
    const b = imageBox(el, s, ctx, CONTENT_W);
    return b ? [b.w, b.w] : [0, 0];
  }
  const tokens: Token[] = [];
  for (const c of el.children) if (!isEl(c) || isInline(c, ctx) || c.tag === "br") inlineTokens(c, ctx, tokens, CONTENT_W);
  let min = 0;
  let max = 0;
  let line = 0;
  for (const t of tokens) {
    const w = t.kind === "word" ? t.w : t.kind === "space" ? t.w : t.kind === "box" ? t.box.w : 0;
    if (t.kind === "word" || t.kind === "box") min = Math.max(min, w);
    if (t.kind === "break") {
      max = Math.max(max, line);
      line = 0;
    } else line += w;
  }
  max = Math.max(max, line);
  for (const c of el.children) {
    if (isEl(c) && !isInline(c, ctx) && c.tag !== "br") {
      const [a, b] = intrinsic(c, ctx);
      const cs = ctx.styler.get(c);
      const extra = cs.padding[1] + cs.padding[3] + cs.margin[1] + cs.margin[3];
      min = Math.max(min, a + extra);
      max = Math.max(max, b + extra);
    }
  }
  const pad = s.padding[1] + s.padding[3] + (s.borderSides?.w ?? 0) * 2;
  return [Math.min(min, CONTENT_W) + pad, Math.min(max, CONTENT_W) + pad];
}

/** A flex row (no wrapping): fixed-width children keep their width, the rest share what's left. */
function flexRow(el: El, width: number, ctx: Ctx): Item {
  const s = ctx.styler.get(el);
  const kids = el.children.filter((c): c is El => isEl(c) && ctx.styler.get(c).display !== "none");
  const gap = s.gap;
  const fixed = kids.map((k) => {
    const ks = ctx.styler.get(k);
    if (k.tag === "img") return intrinsic(k, ctx)[1];
    if (ks.width) return ks.width;
    if (ks.minWidth) return ks.minWidth;
    return null;
  });
  const free = Math.max(0, width - gap * (kids.length - 1) - fixed.reduce<number>((a, b) => a + (b ?? 0), 0));
  const flexible = fixed.filter((f) => f === null).length;
  const widths = fixed.map((f) => f ?? (flexible ? free / flexible : 0));
  const boxes = kids.map((k, i) => (k.tag === "img" ? imageBox(k, ctx.styler.get(k), ctx, widths[i]) ?? { w: 0, h: 0, draw: () => {} } : layoutBox(k, widths[i], ctx)));
  const h = Math.max(0, ...boxes.map((b) => b.h));
  return {
    h,
    draw: (page, x, top) => {
      let cx = x;
      boxes.forEach((b, i) => {
        const centred = kids[i].tag === "img" ? top - (h - b.h) / 2 : top;
        b.draw(page, cx, centred, kids[i].tag === "img" ? b.h : h);
        cx += widths[i] + gap;
      });
    },
  };
}

/** `grid-template-columns: repeat(N, 1fr)`: rows of N equal cells. */
function gridRows(el: El, width: number, ctx: Ctx): Item[] {
  const s = ctx.styler.get(el);
  const n = s.gridCols;
  const gap = s.gap;
  const colW = (width - gap * (n - 1)) / n;
  const kids = el.children.filter((c): c is El => isEl(c) && ctx.styler.get(c).display !== "none");
  const rows: Item[] = [];
  for (let i = 0; i < kids.length; i += n) {
    const boxes = kids.slice(i, i + n).map((k) => {
      const ks = ctx.styler.get(k);
      return { box: layoutBox(k, colW - ks.margin[1] - ks.margin[3], ctx), ks };
    });
    const h = Math.max(...boxes.map(({ box, ks }) => box.h + ks.margin[0] + ks.margin[2]));
    if (rows.length) rows.push(spacer(gap));
    rows.push({
      h,
      draw: (page, x, top) => boxes.forEach(({ box, ks }, j) => box.draw(page, x + j * (colW + gap) + ks.margin[3], top - ks.margin[0], box.h)),
    });
  }
  return rows;
}

/** A table: column widths from content, one unbreakable item per row, the header repeated after a page break. */
function tableItems(el: El, width: number, ctx: Ctx): Item[] {
  type Row = { cells: El[]; head: boolean };
  const rows: Row[] = [];
  const collect = (n: El, head: boolean) => {
    for (const c of n.children) {
      if (!isEl(c)) continue;
      if (c.tag === "tr") rows.push({ cells: c.children.filter((x): x is El => isEl(x) && (x.tag === "td" || x.tag === "th")), head: head || c.children.every((x) => !isEl(x) || x.tag === "th") });
      else if (c.tag === "thead") collect(c, true);
      else if (c.tag === "tbody" || c.tag === "tfoot") collect(c, false);
    }
  };
  collect(el, false);
  if (!rows.length) return [];
  const span = (c: El) => Math.max(1, Number(c.attrs.colspan) || 1);
  const cols = Math.max(...rows.map((r) => r.cells.reduce((n, c) => n + span(c), 0)));
  const min = new Array<number>(cols).fill(8);
  const max = new Array<number>(cols).fill(8);
  for (const r of rows) {
    let col = 0;
    for (const c of r.cells) {
      if (span(c) === 1) {
        const [a, b] = intrinsic(c, ctx);
        min[col] = Math.max(min[col], a);
        max[col] = Math.max(max[col], b);
      }
      col += span(c);
    }
  }
  const sumMin = min.reduce((a, b) => a + b, 0);
  const sumMax = max.reduce((a, b) => a + b, 0);
  let widths: number[];
  if (sumMax <= width) widths = max.map((m) => m + (width - sumMax) * (m / sumMax));
  else if (sumMin >= width) widths = min.map((m) => (m / sumMin) * width);
  else widths = min.map((m, i) => m + ((max[i] - m) * (width - sumMin)) / (sumMax - sumMin));

  const rowItem = (r: Row): Item => {
    let col = 0;
    const boxes = r.cells.map((c) => {
      const w = widths.slice(col, col + span(c)).reduce((a, b) => a + b, 0);
      const x0 = widths.slice(0, col).reduce((a, b) => a + b, 0);
      col += span(c);
      return { x0, box: layoutBox(c, w, ctx) };
    });
    const h = Math.max(0, ...boxes.map((b) => b.box.h));
    return { h, draw: (page, x, top) => boxes.forEach((b) => b.box.draw(page, x + b.x0, top, h)) };
  };
  const out: Item[] = [];
  let header: Item | undefined;
  for (const r of rows) {
    const item = rowItem(r);
    if (r.head && !header && out.length === 0) {
      header = item;
      out.push({ ...item, keepWithNext: true });
    } else out.push(header ? { ...item, header } : item);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Pagination and drawing

function paginate(doc: PDFDocument, items: Item[]): void {
  let page = doc.addPage([PAGE_W, PAGE_H]);
  let y = PAGE_H - MARGIN_Y;
  const bottom = MARGIN_Y;
  let atTop = true;
  const newPage = () => {
    page = doc.addPage([PAGE_W, PAGE_H]);
    y = PAGE_H - MARGIN_Y;
    atTop = true;
  };
  const nextSolid = (i: number) => {
    let h = 0;
    for (let j = i + 1; j < items.length; j++) {
      h += items[j].h;
      if (!items[j].spacer) return h;
    }
    return h;
  };
  items.forEach((it, i) => {
    if (it.spacer) {
      if (atTop) return;
      if (y - it.h < bottom) {
        newPage();
        return;
      }
      y -= it.h;
      return;
    }
    const need = it.keepWithNext ? it.h + Math.min(nextSolid(i), CONTENT_H / 3) : it.h;
    if (y - need < bottom && !atTop) {
      newPage();
      if (it.header) {
        it.header.draw(page, MARGIN_X, y);
        y -= it.header.h;
      }
    }
    it.draw(page, MARGIN_X, y);
    y -= it.h;
    atTop = false;
  });
}

async function defaultFetchImage(url: string): Promise<Uint8Array | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(IMAGE_FETCH_TIMEOUT_MS), redirect: "follow" });
    if (!res.ok) return null;
    const type = res.headers.get("content-type") ?? "";
    if (!/image\/(png|jpe?g)/i.test(type)) return null;
    const declared = Number(res.headers.get("content-length") ?? 0);
    if (declared > IMAGE_MAX_BYTES) return null;
    const buf = new Uint8Array(await res.arrayBuffer());
    return buf.byteLength > IMAGE_MAX_BYTES ? null : buf;
  } catch {
    return null;
  }
}

async function embedImages(doc: PDFDocument, root: El, fetchImage: (url: string) => Promise<Uint8Array | null>): Promise<Images> {
  const srcs = new Set<string>();
  const walk = (el: El) => {
    if (el.tag === "img" && el.attrs.src) srcs.add(el.attrs.src);
    el.children.forEach((c) => isEl(c) && walk(c));
  };
  walk(root);
  const images: Images = new Map();
  await Promise.all(
    [...srcs].map(async (src) => {
      try {
        let bytes: Uint8Array | null = null;
        const data = /^data:image\/(png|jpe?g);base64,([a-z0-9+/=\s]+)$/i.exec(src);
        if (data) bytes = Uint8Array.from(Buffer.from(data[2], "base64"));
        else if (/^https:\/\//i.test(src)) bytes = await fetchImage(src);
        if (!bytes || bytes.length < 4) return;
        const isPng = bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47;
        const isJpg = bytes[0] === 0xff && bytes[1] === 0xd8;
        if (isPng) images.set(src, await doc.embedPng(bytes));
        else if (isJpg) images.set(src, await doc.embedJpg(bytes));
      } catch {
        // An image that won't decode is left out; the report still renders.
      }
    }),
  );
  return images;
}

export type HtmlPdfOptions = {
  /** Fetches an https image (an Agency logo). Default: fetch with a 5 s and 2 MB cap. Return null to leave it out. */
  fetchImage?: (url: string) => Promise<Uint8Array | null>;
};

/** One of our HTML report templates as PDF bytes, without a browser. */
export async function renderHtmlPdf(html: string, opts: HtmlPdfOptions = {}): Promise<Buffer> {
  const root = parseHtml(html);
  const css: string[] = [];
  const walk = (el: El) => {
    if (el.tag === "style") css.push(textContent(el));
    el.children.forEach((c) => isEl(c) && walk(c));
  };
  walk(root);
  const doc = await PDFDocument.create();
  const title = find(root, "title");
  // The title is the template's own (white-labelled for Agency branding); no
  // author or creator of ours is written, so a branded report never names us.
  if (title) doc.setTitle(textContent(title).replace(/\s+/g, " ").trim());
  doc.setCreator("");
  doc.setProducer("");
  const fonts: Fonts = {
    regular: await doc.embedFont(StandardFonts.Helvetica),
    bold: await doc.embedFont(StandardFonts.HelveticaBold),
    italic: await doc.embedFont(StandardFonts.HelveticaOblique),
    boldItalic: await doc.embedFont(StandardFonts.HelveticaBoldOblique),
    mono: await doc.embedFont(StandardFonts.Courier),
  };
  const ctx: Ctx = { styler: new Styler(parseCss(css.join("\n"))), fonts, images: await embedImages(doc, root, opts.fetchImage ?? defaultFetchImage), lists: [] };
  const body = find(root, "body") ?? root;
  const items = body === root ? contentItems(root, CONTENT_W, ctx) : plainItems(body, CONTENT_W, ctx);
  paginate(doc, items.length ? items : [spacer(0)]);
  return Buffer.from(await doc.save());
}

// Text and colour helpers shared by the pdf-lib renderers (htmlPdf.ts,
// evidencePackPdf.ts). The PDF standard fonts only encode Windows-1252
// (WinAnsi), and pdf-lib throws on anything else, so every string drawn goes
// through toWinAnsi() first: an emoji in a finding title or a non-Latin
// company name must never turn a good report into a 500.
import { rgb, type PDFFont, type RGB } from "pdf-lib";

const charSets = new WeakMap<PDFFont, Set<number>>();
function characterSet(font: PDFFont): Set<number> {
  let set = charSets.get(font);
  if (!set) {
    set = new Set(font.getCharacterSet());
    charSets.set(font, set);
  }
  return set;
}

export function colour(hex: string): RGB {
  const n = Number.parseInt(hex.replace("#", ""), 16);
  return rgb(((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255);
}

// Common characters outside WinAnsi, mapped to a readable equivalent.
const SUBSTITUTES: Record<string, string> = {
  "→": "->",
  "←": "<-",
  "≤": "<=",
  "≥": ">=",
  "≠": "!=",
  "✓": "Yes",
  "✔": "Yes",
  "✗": "No",
  "✘": "No",
  "Ł": "L",
  "ł": "l",
  "Đ": "D",
  "đ": "d",
  "−": "-",
  "‑": "-",
  " ": " ",
  " ": " ",
  " ": " ",
};

/**
 * Pure: `text` restricted to what `font` can encode. Whitespace (newlines and
 * tabs included) collapses to single spaces, known symbols are spelled out,
 * accents a font lacks are dropped, and anything else becomes "?".
 */
export function toWinAnsi(text: string, font: PDFFont): string {
  const supported = characterSet(font);
  let out = "";
  for (const ch of text.replace(/\s+/g, " ")) {
    const cp = ch.codePointAt(0) ?? 63;
    if (supported.has(cp)) {
      out += ch;
      continue;
    }
    const sub = SUBSTITUTES[ch];
    if (sub !== undefined) {
      out += sub;
      continue;
    }
    const bare = ch.normalize("NFD").replace(/[̀-ͯ]/g, "");
    out += bare && [...bare].every((c) => supported.has(c.codePointAt(0) ?? -1)) ? bare : "?";
  }
  return out.trim();
}

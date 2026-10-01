// Minimal YAML and TOML readers for lockfiles — just enough syntax for what
// pnpm, Yarn (berry), Poetry and Cargo actually write, so the lockfile
// parsers in dependencyLockfiles.ts don't need a YAML or TOML dependency.
// Machine-written lockfiles use a small, regular subset of each language;
// these readers cover that subset and are tolerant of the rest (anything
// unrecognised is skipped or kept as a raw string), never throwing on
// content they merely don't understand.
//
// Not general-purpose parsers: no anchors/aliases/tags or multi-line flow
// collections in YAML (flow `{...}`/`[...]` values stay raw strings), no
// dates or multi-line keys in TOML. Don't reuse them for config files a
// human edits.

export type YamlValue = string | null | YamlValue[] | { [key: string]: YamlValue };

type YamlLine = { indent: number; text: string };

function unquoteYaml(s: string): string {
  if (s.length >= 2 && s.startsWith("'") && s.endsWith("'")) return s.slice(1, -1).replace(/''/g, "'");
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
    try {
      return JSON.parse(s) as string;
    } catch {
      return s.slice(1, -1);
    }
  }
  return s;
}

/** Splits "key: value" (key possibly quoted). Null when the line isn't a mapping entry. */
function splitYamlKey(text: string): { key: string; rest: string } | null {
  if (text.startsWith("'") || text.startsWith('"')) {
    const q = text[0];
    let i = 1;
    while (i < text.length) {
      if (text[i] === q) {
        if (q === "'" && text[i + 1] === "'") {
          i += 2;
          continue;
        }
        break;
      }
      if (q === '"' && text[i] === "\\") i++;
      i++;
    }
    const after = text.slice(i + 1);
    if (!after.startsWith(":")) return null;
    return { key: unquoteYaml(text.slice(0, i + 1)), rest: after.slice(1).trim() };
  }
  const sep = text.indexOf(": ");
  if (sep > 0) return { key: text.slice(0, sep).trim(), rest: text.slice(sep + 2).trim() };
  if (text.endsWith(":")) return { key: text.slice(0, -1).trim(), rest: "" };
  return null;
}

function yamlScalar(raw: string): YamlValue {
  let s = raw.trim();
  if (!s.startsWith("'") && !s.startsWith('"')) {
    const hash = s.indexOf(" #");
    if (hash >= 0) s = s.slice(0, hash).trim();
  }
  if (s === "" || s === "~" || s === "null") return null;
  return unquoteYaml(s);
}

function isSeqItem(text: string): boolean {
  return text === "-" || text.startsWith("- ");
}

function parseYamlBlock(lines: YamlLine[], start: number, indent: number): [YamlValue, number] {
  return isSeqItem(lines[start].text) ? parseYamlSeq(lines, start, indent) : parseYamlMap(lines, start, indent);
}

function parseYamlSeq(lines: YamlLine[], start: number, indent: number): [YamlValue, number] {
  const out: YamlValue[] = [];
  let i = start;
  while (i < lines.length && lines[i].indent === indent && isSeqItem(lines[i].text)) {
    const item = lines[i].text.slice(1).trim();
    i++;
    if (item === "" && i < lines.length && lines[i].indent > indent) {
      const [v, ni] = parseYamlBlock(lines, i, lines[i].indent);
      out.push(v);
      i = ni;
    } else {
      out.push(yamlScalar(item));
    }
    while (i < lines.length && lines[i].indent > indent) i++; // nested content we don't model
  }
  return [out, i];
}

function parseYamlMap(lines: YamlLine[], start: number, indent: number): [YamlValue, number] {
  const out: { [key: string]: YamlValue } = {};
  let i = start;
  while (i < lines.length && lines[i].indent >= indent) {
    const line = lines[i];
    if (line.indent > indent || isSeqItem(line.text)) {
      i++; // stray deeper line, or a sequence where a key was expected: skip
      continue;
    }
    const kv = splitYamlKey(line.text);
    i++;
    if (!kv) continue;
    if (kv.rest === "") {
      if (i < lines.length && lines[i].indent > indent) {
        const [v, ni] = parseYamlBlock(lines, i, lines[i].indent);
        out[kv.key] = v;
        i = ni;
      } else if (i < lines.length && lines[i].indent === indent && isSeqItem(lines[i].text)) {
        // YAML allows a sequence at the same indent as its parent key.
        const [v, ni] = parseYamlSeq(lines, i, indent);
        out[kv.key] = v;
        i = ni;
      } else {
        out[kv.key] = null;
      }
    } else if (/^[|>][-+0-9]*$/.test(kv.rest)) {
      // Block scalar: keep its text, joined.
      const parts: string[] = [];
      while (i < lines.length && lines[i].indent > indent) parts.push(lines[i++].text);
      out[kv.key] = parts.join(kv.rest.startsWith("|") ? "\n" : " ");
    } else {
      out[kv.key] = yamlScalar(kv.rest);
    }
  }
  return [out, i];
}

/** Every document in `raw` (split on `---`), each as nested maps/sequences/strings. */
export function parseYamlDocuments(raw: string): YamlValue[] {
  const docs: YamlLine[][] = [[]];
  for (const rawLine of raw.replace(/^﻿/, "").split(/\r?\n/)) {
    if (/^---(\s|$)/.test(rawLine)) {
      docs.push([]);
      continue;
    }
    if (/^\.\.\.\s*$/.test(rawLine)) continue;
    const text = rawLine.trim();
    if (text === "" || text.startsWith("#")) continue;
    const indent = rawLine.length - rawLine.trimStart().length;
    docs[docs.length - 1].push({ indent, text });
  }
  return docs.filter((d) => d.length > 0).map((lines) => parseYamlBlock(lines, 0, lines[0].indent)[0]);
}

export function isYamlMap(v: YamlValue | undefined): v is { [key: string]: YamlValue } {
  return v !== null && v !== undefined && typeof v === "object" && !Array.isArray(v);
}

// ---------------------------------------------------------------------------
// TOML

export type TomlTable = { [key: string]: unknown };

class TomlCursor {
  constructor(public s: string, public i = 0) {}
  peek(): string {
    return this.s[this.i] ?? "";
  }
  /** Skips spaces, tabs, newlines and comments (comments only where a value can't be). */
  skipWsAndComments(): void {
    for (;;) {
      const c = this.peek();
      if (c === " " || c === "\t" || c === "\n" || c === "\r") this.i++;
      else if (c === "#") while (this.i < this.s.length && this.peek() !== "\n") this.i++;
      else return;
    }
  }
  skipInlineWs(): void {
    while (this.peek() === " " || this.peek() === "\t") this.i++;
  }
}

const TOML_ESCAPES: Record<string, string> = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", '"': '"', "\\": "\\" };

function readTomlString(c: TomlCursor): string {
  const s = c.s;
  if (s.startsWith('"""', c.i) || s.startsWith("'''", c.i)) {
    const q = s.slice(c.i, c.i + 3);
    const end = s.indexOf(q, c.i + 3);
    const body = s.slice(c.i + 3, end < 0 ? s.length : end).replace(/^\r?\n/, "");
    c.i = end < 0 ? s.length : end + 3;
    return q === '"""' ? body.replace(/\\(.)/g, (_, ch: string) => TOML_ESCAPES[ch] ?? ch) : body;
  }
  const q = s[c.i++];
  let out = "";
  while (c.i < s.length && s[c.i] !== q && s[c.i] !== "\n") {
    if (q === '"' && s[c.i] === "\\") {
      const ch = s[c.i + 1];
      if (ch === "u" || ch === "U") {
        const len = ch === "u" ? 4 : 8;
        out += String.fromCodePoint(parseInt(s.slice(c.i + 2, c.i + 2 + len), 16) || 0xfffd);
        c.i += 2 + len;
        continue;
      }
      out += TOML_ESCAPES[ch] ?? ch;
      c.i += 2;
      continue;
    }
    out += s[c.i++];
  }
  c.i++; // closing quote
  return out;
}

function readTomlKeyPart(c: TomlCursor): string {
  c.skipInlineWs();
  if (c.peek() === '"' || c.peek() === "'") return readTomlString(c);
  const m = /^[A-Za-z0-9_-]+/.exec(c.s.slice(c.i));
  if (!m) return "";
  c.i += m[0].length;
  return m[0];
}

function readTomlKey(c: TomlCursor): string[] {
  const parts = [readTomlKeyPart(c)];
  c.skipInlineWs();
  while (c.peek() === ".") {
    c.i++;
    parts.push(readTomlKeyPart(c));
    c.skipInlineWs();
  }
  return parts;
}

function setPath(table: TomlTable, path: string[], value: unknown): void {
  let t = table;
  for (const p of path.slice(0, -1)) {
    if (!t[p] || typeof t[p] !== "object" || Array.isArray(t[p])) t[p] = {};
    t = t[p] as TomlTable;
  }
  t[path[path.length - 1]] = value;
}

function readTomlValue(c: TomlCursor): unknown {
  c.skipInlineWs();
  const ch = c.peek();
  if (ch === '"' || ch === "'") return readTomlString(c);
  if (ch === "[") {
    c.i++;
    const arr: unknown[] = [];
    for (;;) {
      c.skipWsAndComments();
      if (c.peek() === "]" || c.peek() === "") {
        c.i++;
        return arr;
      }
      arr.push(readTomlValue(c));
      c.skipWsAndComments();
      if (c.peek() === ",") c.i++;
    }
  }
  if (ch === "{") {
    c.i++;
    const obj: TomlTable = {};
    for (;;) {
      c.skipInlineWs();
      if (c.peek() === "}" || c.peek() === "" || c.peek() === "\n") {
        c.i++;
        return obj;
      }
      const key = readTomlKey(c);
      c.skipInlineWs();
      if (c.peek() !== "=") return obj;
      c.i++;
      setPath(obj, key, readTomlValue(c));
      c.skipInlineWs();
      if (c.peek() === ",") c.i++;
    }
  }
  const m = /^[^\s,\]}#]+/.exec(c.s.slice(c.i));
  const tok = m ? m[0] : "";
  c.i += tok.length;
  if (tok === "true") return true;
  if (tok === "false") return false;
  if (/^[+-]?\d[\d_]*$/.test(tok)) return Number(tok.replace(/_/g, ""));
  if (/^[+-]?\d[\d_]*(\.\d+)?([eE][+-]?\d+)?$/.test(tok)) return Number(tok.replace(/_/g, ""));
  return tok;
}

/** Walks to (creating) the table at `path`; an array-of-tables segment resolves to its last element. */
function tableAt(root: TomlTable, path: string[]): TomlTable {
  let t = root;
  for (const p of path) {
    const existing = t[p];
    if (Array.isArray(existing)) {
      const last = existing[existing.length - 1];
      t = last && typeof last === "object" ? (last as TomlTable) : t;
    } else if (existing && typeof existing === "object") {
      t = existing as TomlTable;
    } else {
      const created: TomlTable = {};
      t[p] = created;
      t = created;
    }
  }
  return t;
}

/** Parses a TOML document into nested plain objects. Unparseable lines are skipped. */
export function parseToml(raw: string): TomlTable {
  const root: TomlTable = {};
  let current = root;
  const c = new TomlCursor(raw.replace(/^﻿/, "").replace(/\r\n/g, "\n"));

  while (c.i < c.s.length) {
    c.skipWsAndComments();
    if (c.i >= c.s.length) break;

    if (c.peek() === "[") {
      const isArray = c.s.startsWith("[[", c.i);
      c.i += isArray ? 2 : 1;
      const path = readTomlKey(c).filter((p) => p !== "");
      while (c.i < c.s.length && c.peek() !== "\n") c.i++;
      if (path.length === 0) continue;
      if (isArray) {
        const parent = tableAt(root, path.slice(0, -1));
        const last = path[path.length - 1];
        if (!Array.isArray(parent[last])) parent[last] = [];
        const created: TomlTable = {};
        (parent[last] as TomlTable[]).push(created);
        current = created;
      } else {
        current = tableAt(root, path);
      }
      continue;
    }

    const start = c.i;
    const key = readTomlKey(c);
    c.skipInlineWs();
    if (key[0] === "" || c.peek() !== "=") {
      // Not a key/value line we understand: skip to the next line.
      c.i = Math.max(c.i, start + 1);
      while (c.i < c.s.length && c.peek() !== "\n") c.i++;
      continue;
    }
    c.i++;
    setPath(current, key, readTomlValue(c));
    while (c.i < c.s.length && c.peek() !== "\n") c.i++; // trailing comment
  }
  return root;
}

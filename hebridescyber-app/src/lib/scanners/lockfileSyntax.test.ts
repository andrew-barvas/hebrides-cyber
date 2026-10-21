// Unit tests for the minimal YAML/TOML readers lockfile parsing relies on.
// These are deliberately partial parsers (see the module header), so the tests
// pin both the subset they DO handle and the "tolerant, never throws" contract
// on everything else.
import { describe, it, expect } from "vitest";
import { parseYamlDocuments, isYamlMap, parseToml, type YamlValue } from "./lockfileSyntax";

/** First document as a map, for the common single-doc case. */
function doc(raw: string): Record<string, YamlValue> {
  const [first] = parseYamlDocuments(raw);
  if (!isYamlMap(first)) throw new Error("expected a map document");
  return first;
}

describe("parseYamlDocuments", () => {
  it("reads a flat map of scalars", () => {
    expect(doc("name: lodash\nversion: 4.17.21\n")).toEqual({ name: "lodash", version: "4.17.21" });
  });

  it("reads nested maps by indentation", () => {
    const d = doc("dependencies:\n  lodash: 4.17.21\n  axios: 1.6.0\n");
    expect(d).toEqual({ dependencies: { lodash: "4.17.21", axios: "1.6.0" } });
  });

  it("reads a block sequence at a deeper indent", () => {
    const d = doc("deps:\n  - a\n  - b\n  - c\n");
    expect(d.deps).toEqual(["a", "b", "c"]);
  });

  it("reads a sequence at the same indent as its parent key (valid YAML)", () => {
    const d = doc("deps:\n- a\n- b\n");
    expect(d.deps).toEqual(["a", "b"]);
  });

  it("reads a sequence of maps where the first key is on the line after the dash", () => {
    // This minimal parser models a map-in-sequence only when the `-` is alone
    // and the map body is indented beneath it (the shape `parseYamlBlock`
    // recurses into) — not the inline `- key: val` form (see next test).
    const d = doc("packages:\n  -\n    name: a\n    version: 1\n  -\n    name: b\n    version: 2\n");
    expect(d.packages).toEqual([
      { name: "a", version: "1" },
      { name: "b", version: "2" },
    ]);
  });

  it("keeps an inline `- key: val` sequence item as a raw scalar (documented parser limitation)", () => {
    // The readers are deliberately partial (module header): an inline map after
    // a dash is kept as a string rather than recursed into. Lockfiles don't use
    // this shape, so it's a tolerated gap, pinned here so a future change is a
    // deliberate decision rather than a silent regression.
    const d = doc("packages:\n  - name: a\n  - name: b\n");
    expect(d.packages).toEqual(["name: a", "name: b"]);
  });

  it("treats ~, null and empty as null", () => {
    expect(doc("a: ~\nb: null\nc:\n")).toEqual({ a: null, b: null, c: null });
  });

  it("strips an inline comment from an unquoted scalar but keeps '#' inside quotes", () => {
    const d = doc(`a: value # trailing\nb: "has # hash"\n`);
    expect(d.a).toBe("value");
    expect(d.b).toBe("has # hash");
  });

  it("skips whole-line comments and blank lines", () => {
    expect(doc("# a comment\n\nname: x\n# another\n")).toEqual({ name: "x" });
  });

  it("unquotes single- and double-quoted scalars, honouring escapes", () => {
    const d = doc(`a: 'it''s fine'\nb: "line\\tbreak"\n`);
    expect(d.a).toBe("it's fine");
    expect(d.b).toBe("line\tbreak");
  });

  it("handles a quoted key containing a colon", () => {
    const d = doc(`"@scope/pkg:1.0": resolved\n`);
    expect(d["@scope/pkg:1.0"]).toBe("resolved");
  });

  it("reads a literal (|) block scalar joined by newlines and a folded (>) one by spaces", () => {
    // Lines are pre-trimmed before parsing, so block-scalar indentation isn't
    // preserved — fine for the lockfile fields this reads (never significant
    // whitespace), and pinned here so the behaviour is explicit.
    const d = doc("lit: |\n  line one\n  line two\nfold: >\n  a\n  b\n");
    expect(d.lit).toBe("line one\nline two");
    expect(d.fold).toBe("a b");
  });

  it("splits multiple documents on ---", () => {
    const docs = parseYamlDocuments("a: 1\n---\nb: 2\n");
    expect(docs).toHaveLength(2);
    expect(docs[0]).toEqual({ a: "1" });
    expect(docs[1]).toEqual({ b: "2" });
  });

  it("ignores a document end marker (...) and a leading BOM", () => {
    const docs = parseYamlDocuments("\uFEFFa: 1\n...\n");
    expect(docs).toEqual([{ a: "1" }]);
  });

  it("tolerates CRLF line endings", () => {
    expect(doc("a: 1\r\nb: 2\r\n")).toEqual({ a: "1", b: "2" });
  });

  it("keeps a pnpm-style quoted dependency path map", () => {
    const d = doc(`'/lodash@4.17.21':\n  resolution:\n    integrity: sha512-abc\n`);
    expect(d["/lodash@4.17.21"]).toEqual({ resolution: { integrity: "sha512-abc" } });
  });

  it("returns an empty array for blank or comment-only input", () => {
    expect(parseYamlDocuments("")).toEqual([]);
    expect(parseYamlDocuments("# only a comment\n")).toEqual([]);
  });
});

describe("isYamlMap", () => {
  it("is true only for a plain object", () => {
    expect(isYamlMap({ a: "1" })).toBe(true);
    expect(isYamlMap(["a"])).toBe(false);
    expect(isYamlMap("a")).toBe(false);
    expect(isYamlMap(null)).toBe(false);
    expect(isYamlMap(undefined)).toBe(false);
  });
});

describe("parseToml", () => {
  it("reads top-level key/value pairs with typed scalars", () => {
    const t = parseToml(`name = "demo"\nversion = 2\nenabled = true\nratio = 1.5\n`);
    expect(t).toEqual({ name: "demo", version: 2, enabled: true, ratio: 1.5 });
  });

  it("reads a [table] header", () => {
    const t = parseToml(`[package]\nname = "demo"\nversion = "1.0.0"\n`);
    expect(t.package).toEqual({ name: "demo", version: "1.0.0" });
  });

  it("reads a dotted-key table path", () => {
    const t = parseToml(`[a.b.c]\nx = 1\n`);
    expect(t).toEqual({ a: { b: { c: { x: 1 } } } });
  });

  it("reads an array-of-tables ([[...]]) as a list", () => {
    const t = parseToml(`[[package]]\nname = "a"\n\n[[package]]\nname = "b"\n`);
    expect(t.package).toEqual([{ name: "a" }, { name: "b" }]);
  });

  it("reads an inline table", () => {
    const t = parseToml(`dep = { name = "a", version = "1.0" }\n`);
    expect(t.dep).toEqual({ name: "a", version: "1.0" });
  });

  it("reads arrays, including arrays of inline tables across lines", () => {
    const t = parseToml(`list = [1, 2, 3]\npkgs = [\n  { name = "a" },\n  { name = "b" },\n]\n`);
    expect(t.list).toEqual([1, 2, 3]);
    expect(t.pkgs).toEqual([{ name: "a" }, { name: "b" }]);
  });

  it("handles underscores in numbers and a dotted key inside a table", () => {
    const t = parseToml(`[x]\nbig = 1_000_000\na.b = "nested"\n`);
    expect(t.x).toEqual({ big: 1000000, a: { b: "nested" } });
  });

  it("reads basic and literal strings, with escapes only in basic strings", () => {
    const t = parseToml(`a = "tab\\there"\nb = 'raw\\nliteral'\n`);
    expect(t.a).toBe("tab\there");
    expect(t.b).toBe("raw\\nliteral");
  });

  it("reads a multi-line basic string, trimming the leading newline", () => {
    const t = parseToml(`msg = """\nhello\nworld"""\n`);
    expect(t.msg).toBe("hello\nworld");
  });

  it("decodes a \\u escape in a basic string", () => {
    const t = parseToml(`a = "\\u0041"\n`);
    expect(t.a).toBe("A");
  });

  it("skips a comment line and a trailing comment after a value", () => {
    const t = parseToml(`# header comment\nname = "demo" # inline\n`);
    expect(t).toEqual({ name: "demo" });
  });

  it("skips a line it cannot parse rather than throwing, keeping the rest", () => {
    const t = parseToml(`good = 1\nthis is not toml\nalso_good = 2\n`);
    expect(t.good).toBe(1);
    expect(t.also_good).toBe(2);
  });

  it("tolerates a BOM and CRLF", () => {
    const t = parseToml(`\uFEFFname = "demo"\r\nversion = 1\r\n`);
    expect(t).toEqual({ name: "demo", version: 1 });
  });

  it("parses a representative Cargo.lock shape", () => {
    const t = parseToml(`version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.197"\n\n[[package]]\nname = "libc"\nversion = "0.2.153"\n`);
    expect(t.version).toBe(3);
    expect(t.package).toEqual([
      { name: "serde", version: "1.0.197" },
      { name: "libc", version: "0.2.153" },
    ]);
  });

  it("returns an empty table for empty input", () => {
    expect(parseToml("")).toEqual({});
    expect(parseToml("# just a comment\n")).toEqual({});
  });
});

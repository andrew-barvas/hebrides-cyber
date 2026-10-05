import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadExpectations, parseExpectation } from "./expectations";

const SCOPE = ["headers", "exposure"];
const FILE = "/x/t.json";

const valid = () => ({
  target: "t",
  description: "d",
  mustFind: ["headers.a"],
  mustNotFind: ["exposure.exposed-file:*"],
  optional: ["headers.b"],
  knownIssues: [{ checkId: "headers.a", kind: "miss", note: "why" }],
});

describe("parseExpectation", () => {
  it("accepts a valid file and defaults omitted lists to empty", () => {
    expect(parseExpectation(valid(), FILE, SCOPE).mustFind).toEqual(["headers.a"]);
    const minimal = parseExpectation({ target: "t", description: "d" }, FILE, SCOPE);
    expect(minimal).toEqual({ target: "t", description: "d", mustFind: [], mustNotFind: [], optional: [], knownIssues: [] });
  });

  it.each([
    ["not an object", null, /must be a JSON object/],
    ["an array", [], /must be a JSON object/],
    ["wrong target", { ...valid(), target: "other" }, /must equal the file name/],
    ["missing description", { ...valid(), description: "" }, /"description" is required/],
    ["non-array list", { ...valid(), mustFind: "headers.a" }, /array of non-empty strings/],
    ["empty string entry", { ...valid(), optional: [""] }, /array of non-empty strings/],
    ["non-string entry", { ...valid(), optional: [1] }, /array of non-empty strings/],
    ["bare wildcard", { ...valid(), mustFind: ["*"] }, /needs a "<module>\." prefix/],
    ["out-of-scope module", { ...valid(), mustFind: ["dns.spf-missing"] }, /not in a module the benchmark drives/],
    ["in both lists", { ...valid(), mustNotFind: ["headers.a"] }, /both mustFind and mustNotFind/],
    ["knownIssues not array", { ...valid(), knownIssues: {} }, /"knownIssues" must be an array/],
    ["knownIssues item not object", { ...valid(), knownIssues: [null] }, /knownIssues\[0\] must be an object/],
    ["bad kind", { ...valid(), knownIssues: [{ checkId: "headers.a", kind: "x", note: "n" }] }, /kind must be/],
    ["missing note", { ...valid(), knownIssues: [{ checkId: "headers.a", kind: "miss" }] }, /must explain the defect/],
    ["bad checkId", { ...valid(), knownIssues: [{ checkId: "dns.x", kind: "miss", note: "n" }] }, /not in a module/],
  ])("rejects %s", (_name, input, message) => {
    expect(() => parseExpectation(input, FILE, SCOPE)).toThrow(message);
  });
});

describe("loadExpectations", () => {
  let dir = "";

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "bench-exp-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("loads every json file keyed by target and ignores other files", () => {
    writeFileSync(path.join(dir, "t.json"), JSON.stringify(valid()));
    writeFileSync(path.join(dir, "u.json"), JSON.stringify({ ...valid(), target: "u" }));
    writeFileSync(path.join(dir, "README.md"), "ignored");
    const out = loadExpectations(dir, SCOPE);
    expect([...out.keys()]).toEqual(["t", "u"]);
  });

  it("names the file when the JSON is invalid", () => {
    writeFileSync(path.join(dir, "bad.json"), "{nope");
    expect(() => loadExpectations(dir, SCOPE)).toThrow(/bad\.json: invalid JSON/);
  });

  it("propagates validation errors", () => {
    writeFileSync(path.join(dir, "t.json"), JSON.stringify({ ...valid(), description: "" }));
    expect(() => loadExpectations(dir, SCOPE)).toThrow(/"description" is required/);
  });
});

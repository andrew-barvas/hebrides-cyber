import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseInjections, parametersRuledOut, runProblem } from "./commixOutput";

const clean = readFileSync(join(__dirname, "fixtures", "commix", "clean.stdout.txt"), "utf8");

describe("commix output (captured real run)", () => {
  it("finds no injection and one ruled-out parameter in the real negative run", () => {
    expect(parseInjections(clean)).toEqual([]);
    expect(parametersRuledOut(clean)).toBe(1);
    expect(runProblem(clean)).toBeNull();
  });
});

describe("parseInjections", () => {
  it("reads both positive wordings, with colour codes and carriage returns, de-duplicated", () => {
    const out = [
      "\u001b[1m[12:00:00] [info] The GET parameter 'addr' seems injectable via (results-based) classic command injection technique.\u001b[0m",
      "progress...\r",
      "[12:00:01] [critical] POST parameter 'host' is vulnerable to command injection.",
      "[12:00:02] [info] The GET parameter 'addr' seems injectable via (time-based) blind technique.",
      "[12:00:03] [info] The parameter 'bare' seems injectable.",
    ].join("\n");
    expect(parseInjections(out)).toEqual([
      { parameter: "addr", place: "GET" },
      { parameter: "host", place: "POST" },
      { parameter: "bare", place: "GET" },
    ]);
  });
});

describe("runProblem", () => {
  it("reports an unreachable target as an error", () => {
    expect(runProblem("[critical] Unable to connect to the target URL.")).toEqual({ kind: "error", note: "commix could not reach the target" });
  });
  it("reports nothing to test as not_applicable", () => {
    expect(runProblem("[critical] No parameter(s) found for testing in the provided data")).toEqual({ kind: "not_applicable", note: "commix found no parameters to test" });
  });
  it("treats an unfinished run as an error, never clean", () => {
    expect(runProblem("[info] Testing the boolean-based blind command injection technique...")?.kind).toBe("error");
  });
  it("errors when it finished but ruled out no parameter", () => {
    expect(runProblem("[critical] All tested parameters do not appear to be injectable.")?.note).toMatch(/without testing/);
  });
  it("is null when an injection was reported", () => {
    expect(runProblem("The GET parameter 'a' seems injectable via x")).toBeNull();
  });
});

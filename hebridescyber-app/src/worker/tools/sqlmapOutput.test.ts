import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  countParametersTested,
  mergeInjectionPoints,
  parseReportedBlocks,
  parseResultsCsv,
  runProblem,
  stripTerminalCodes,
} from "./sqlmapOutput";

const fixture = (name: string) => readFileSync(join(__dirname, "fixtures", "sqlmap", name), "utf8");

describe("parseReportedBlocks (captured real output)", () => {
  it("reads the injection point and DBMS from the console output", () => {
    const [point, ...rest] = parseReportedBlocks(fixture("vulnerable.stdout.txt"));
    expect(rest).toEqual([]);
    expect(point).toMatchObject({ parameter: "id", place: "GET", dbms: "SQLite", url: null });
    expect(point.techniques).toEqual([
      "boolean-based blind",
      "error-based",
      "time-based blind",
      "UNION query",
    ]);
  });

  it("reads the same point from the per-host log file", () => {
    const [point] = parseReportedBlocks(fixture("vulnerable.host-log.txt"));
    expect(point).toMatchObject({ parameter: "id", place: "GET", dbms: "SQLite" });
  });

  it("finds nothing in a clean run", () => {
    expect(parseReportedBlocks(fixture("clean.stdout.txt"))).toEqual([]);
  });

  it("separates several parameters and blocks, each with its own DBMS", () => {
    const text = [
      "sqlmap identified the following injection point(s) with a total of 9 HTTP(s) requests:",
      "---",
      "Parameter: id (GET)",
      "    Type: error-based",
      "",
      "Parameter: name (POST)",
      "    Type: boolean-based blind",
      "    Type: UNION query",
      "---",
      "back-end DBMS: MySQL >= 5.0",
      "sqlmap identified the following injection point(s) with a total of 5 HTTP(s) requests:",
      "---",
      "Parameter: #1* (URI)",
      "    Type: time-based blind",
      "---",
    ].join("\n");
    const points = parseReportedBlocks(text);
    expect(points.map((p) => `${p.place}:${p.parameter}:${p.dbms}`)).toEqual([
      "GET:id:MySQL >= 5.0",
      "POST:name:MySQL >= 5.0",
      "URI:#1*:null",
    ]);
    expect(points[1].techniques).toEqual(["boolean-based blind", "UNION query"]);
  });
});

describe("parseResultsCsv (captured real output)", () => {
  it("reads one row per affected parameter, with the page and technique names", () => {
    expect(parseResultsCsv(fixture("vulnerable.results.csv"))).toEqual([
      {
        parameter: "id",
        place: "GET",
        techniques: ["boolean-based blind", "error-based", "time-based blind", "UNION query"],
        dbms: null,
        url: "http://127.0.0.1:8099/item?id=1",
      },
    ]);
  });

  it("returns nothing for a header-only file", () => {
    expect(parseResultsCsv(fixture("clean.results.csv"))).toEqual([]);
  });

  it("handles quoted fields, blank lines and incomplete rows", () => {
    const csv = ['Target URL,Place,Parameter,Technique(s),Note(s)', '"http://x.test/a?b=1,2",POST,q,S,', "", "http://x.test/,,,,", 'http://x.test/z,GET,"a""b",X,'].join("\n");
    expect(parseResultsCsv(csv)).toEqual([
      { parameter: "q", place: "POST", techniques: ["stacked queries"], dbms: null, url: "http://x.test/a?b=1,2" },
      { parameter: 'a"b', place: "GET", techniques: [], dbms: null, url: "http://x.test/z" },
    ]);
  });

  it("tolerates a row with fewer fields than the header", () => {
    expect(parseResultsCsv("h\nhttp://x.test/,GET,id")).toEqual([
      { parameter: "id", place: "GET", techniques: [], dbms: null, url: "http://x.test/" },
    ]);
    expect(parseResultsCsv("h\n,GET,id")[0].url).toBeNull();
  });
});

describe("mergeInjectionPoints", () => {
  it("merges the console block and the CSV row into one entry", () => {
    const merged = mergeInjectionPoints([parseReportedBlocks(fixture("vulnerable.stdout.txt")), parseResultsCsv(fixture("vulnerable.results.csv"))]);
    expect(merged).toHaveLength(1);
    expect(merged[0]).toMatchObject({ parameter: "id", place: "GET", dbms: "SQLite", url: "http://127.0.0.1:8099/item?id=1" });
    expect(merged[0].techniques).toHaveLength(4);
  });

  it("keeps different places apart and treats place case-insensitively", () => {
    const point = { parameter: "id", techniques: [], dbms: null, url: null };
    const merged = mergeInjectionPoints([[{ ...point, place: "GET" }, { ...point, place: "POST" }], [{ ...point, place: "get", techniques: ["error-based"], dbms: "SQLite", url: "http://x/" }]]);
    expect(merged).toHaveLength(2);
    expect(merged[0]).toMatchObject({ place: "GET", techniques: ["error-based"], dbms: "SQLite", url: "http://x/" });
  });

  it("does not overwrite a known DBMS or URL, nor repeat a technique", () => {
    const base = { parameter: "id", place: "GET", techniques: ["error-based"], dbms: "A", url: "http://a/" };
    const [merged] = mergeInjectionPoints([[base], [{ ...base, dbms: "B", url: "http://b/" }]]);
    expect(merged).toMatchObject({ dbms: "A", url: "http://a/", techniques: ["error-based"] });
  });
});

describe("run evidence", () => {
  it("counts the distinct parameters sqlmap probed", () => {
    expect(countParametersTested(fixture("vulnerable.stdout.txt"))).toBe(2);
    expect(countParametersTested(fixture("clean.stdout.txt"))).toBe(2);
    expect(countParametersTested(fixture("unreachable.stdout.txt"))).toBe(0);
  });

  it("accepts a run that reached its closing line", () => {
    expect(runProblem(fixture("vulnerable.stdout.txt"))).toBeNull();
    expect(runProblem(fixture("clean.stdout.txt"))).toBeNull();
  });

  it("reports an unreachable target, or a run that stopped early", () => {
    expect(runProblem(fixture("unreachable.stdout.txt"))).toContain("unable to connect to the target URL ('Connection refused')");
    expect(runProblem("[INFO] testing something\n")).toBe("sqlmap stopped before it finished");
  });

  it("strips terminal control codes", () => {
    expect(stripTerminalCodes("\x1b)0\x1b[1;24r\x1b[24;1Hhello\x1b[m")).toBe("hello");
  });
});

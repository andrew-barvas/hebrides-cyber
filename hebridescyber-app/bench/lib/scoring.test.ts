import { describe, expect, it } from "vitest";
import {
  aggregate,
  diffBaseline,
  formatTable,
  matches,
  metricsFor,
  moduleOf,
  scoreTarget,
  toBaseline,
  type Expectation,
  type ModuleMetrics,
} from "./scoring";

const SCOPE = ["headers", "exposure", "directory-listing"];

function exp(partial: Partial<Expectation> = {}): Expectation {
  return {
    target: "t",
    description: "d",
    mustFind: [],
    mustNotFind: [],
    optional: [],
    knownIssues: [],
    ...partial,
  };
}

describe("moduleOf / matches", () => {
  it("takes the prefix before the first dot", () => {
    expect(moduleOf("exposure.exposed-file:/.env")).toBe("exposure");
    expect(moduleOf("directory-listing.open-directory:/a/")).toBe("directory-listing");
    expect(moduleOf("bare")).toBe("bare");
  });

  it("matches exactly or by prefix wildcard", () => {
    expect(matches("headers.csp-absent", "headers.csp-absent")).toBe(true);
    expect(matches("headers.csp-absent", "headers.csp-weak")).toBe(false);
    expect(matches("exposure.exposed-file:*", "exposure.exposed-file:/.env")).toBe(true);
    expect(matches("exposure.exposed-file:*", "exposure.no-security-txt")).toBe(false);
  });
});

describe("scoreTarget", () => {
  it("counts a reported must-find as a true positive", () => {
    const s = scoreTarget(exp({ mustFind: ["headers.csp-absent"] }), ["headers.csp-absent"], SCOPE);
    expect(s.modules.headers).toEqual({ tp: 1, fp: 0, fn: 0 });
    expect(s.failures).toEqual([]);
    expect(s.unexpected).toEqual([]);
  });

  it("matches wildcard must-find patterns once, however many findings satisfy them", () => {
    const s = scoreTarget(
      exp({ mustFind: ["exposure.exposed-file:*"] }),
      ["exposure.exposed-file:/.env", "exposure.exposed-file:/.git/HEAD"],
      SCOPE
    );
    expect(s.modules.exposure).toEqual({ tp: 1, fp: 0, fn: 0 });
  });

  it("records a missing must-find as a false negative and a hard failure", () => {
    const s = scoreTarget(exp({ target: "x", mustFind: ["headers.csp-absent"] }), [], SCOPE);
    expect(s.modules.headers).toEqual({ tp: 0, fp: 0, fn: 1 });
    expect(s.failures).toEqual([{ kind: "missing", target: "x", checkId: "headers.csp-absent" }]);
  });

  it("flags a must-not-find that was reported as a false positive and a hard failure", () => {
    const s = scoreTarget(
      exp({ target: "spa", mustNotFind: ["exposure.exposed-file:*"] }),
      ["exposure.exposed-file:/.env"],
      SCOPE
    );
    expect(s.modules.exposure).toEqual({ tp: 0, fp: 1, fn: 0 });
    expect(s.failures).toEqual([{ kind: "forbidden", target: "spa", checkId: "exposure.exposed-file:/.env" }]);
    expect(s.unexpected).toEqual([]);
  });

  it("counts an unmentioned finding as a false positive without hard-failing", () => {
    const s = scoreTarget(exp(), ["headers.cors-wildcard"], SCOPE);
    expect(s.modules.headers).toEqual({ tp: 0, fp: 1, fn: 0 });
    expect(s.failures).toEqual([]);
    expect(s.unexpected).toEqual(["headers.cors-wildcard"]);
  });

  it("ignores optional findings entirely", () => {
    const s = scoreTarget(exp({ optional: ["headers.info-disclosure"] }), ["headers.info-disclosure"], SCOPE);
    expect(s.modules).toEqual({});
    expect(s.unexpected).toEqual([]);
  });

  it("ignores findings from modules outside the benchmark scope", () => {
    const s = scoreTarget(exp(), ["dns.spf-missing"], SCOPE);
    expect(s.modules).toEqual({});
    expect(s.unexpected).toEqual([]);
  });

  it("de-duplicates reported ids", () => {
    const s = scoreTarget(exp({ mustFind: ["headers.a"] }), ["headers.a", "headers.a"], SCOPE);
    expect(s.found).toEqual(["headers.a"]);
    expect(s.modules.headers.tp).toBe(1);
  });

  it("tolerates a known miss without a hard failure, while still counting the FN", () => {
    const s = scoreTarget(
      exp({
        mustFind: ["directory-listing.open-directory:/assets/"],
        knownIssues: [{ checkId: "directory-listing.open-directory:/assets/", kind: "miss", note: "n" }],
      }),
      [],
      SCOPE
    );
    expect(s.modules["directory-listing"].fn).toBe(1);
    expect(s.failures).toEqual([]);
    expect(s.knownIssuesOpen).toEqual(["directory-listing.open-directory:/assets/"]);
    expect(s.knownIssuesStale).toEqual([]);
  });

  it("tolerates a known false positive without a hard failure, while still counting the FP", () => {
    const s = scoreTarget(
      exp({
        mustNotFind: ["headers.cors-wildcard"],
        knownIssues: [{ checkId: "headers.cors-wildcard", kind: "false-positive", note: "n" }],
      }),
      ["headers.cors-wildcard"],
      SCOPE
    );
    expect(s.modules.headers.fp).toBe(1);
    expect(s.failures).toEqual([]);
    expect(s.knownIssuesOpen).toEqual(["headers.cors-wildcard"]);
  });

  it("reports known issues that no longer reproduce as stale", () => {
    const s = scoreTarget(
      exp({
        mustFind: ["headers.a"],
        knownIssues: [
          { checkId: "headers.a", kind: "miss", note: "n" },
          { checkId: "headers.b", kind: "false-positive", note: "n" },
        ],
      }),
      ["headers.a"],
      SCOPE
    );
    expect(s.knownIssuesOpen).toEqual([]);
    expect(s.knownIssuesStale).toEqual(["headers.a", "headers.b"]);
  });

  it("does not let a false-positive known issue excuse a miss, or vice versa", () => {
    const s = scoreTarget(
      exp({
        target: "k",
        mustFind: ["headers.a"],
        knownIssues: [{ checkId: "headers.a", kind: "false-positive", note: "n" }],
      }),
      [],
      SCOPE
    );
    expect(s.failures).toEqual([{ kind: "missing", target: "k", checkId: "headers.a" }]);
  });
});

describe("metricsFor", () => {
  it("computes precision and recall rounded to four places", () => {
    expect(metricsFor({ tp: 2, fp: 1, fn: 0 })).toEqual({ tp: 2, fp: 1, fn: 0, precision: 0.6667, recall: 1 });
    expect(metricsFor({ tp: 2, fp: 0, fn: 1 })).toEqual({ tp: 2, fp: 0, fn: 1, precision: 1, recall: 0.6667 });
  });

  it("treats empty denominators as perfect", () => {
    expect(metricsFor({ tp: 0, fp: 0, fn: 0 })).toMatchObject({ precision: 1, recall: 1 });
    expect(metricsFor({ tp: 0, fp: 3, fn: 0 })).toMatchObject({ precision: 0, recall: 1 });
    expect(metricsFor({ tp: 0, fp: 0, fn: 3 })).toMatchObject({ precision: 1, recall: 0 });
  });
});

describe("aggregate", () => {
  it("sums counts across targets and sorts modules by name", () => {
    const a = scoreTarget(exp({ mustFind: ["headers.a", "exposure.x"] }), ["headers.a"], SCOPE);
    const b = scoreTarget(exp({ mustFind: ["headers.a"] }), ["headers.a", "headers.z"], SCOPE);
    const out = aggregate([a, b]);
    expect(Object.keys(out)).toEqual(["exposure", "headers"]);
    expect(out.headers).toMatchObject({ tp: 2, fp: 1, fn: 0, precision: 0.6667, recall: 1 });
    expect(out.exposure).toMatchObject({ tp: 0, fp: 0, fn: 1, recall: 0 });
  });

  it("returns an empty object for no targets", () => {
    expect(aggregate([])).toEqual({});
  });
});

describe("diffBaseline", () => {
  const m = (precision: number, recall: number): ModuleMetrics => ({ tp: 0, fp: 0, fn: 0, precision, recall });
  const baseline = toBaseline({ headers: m(1, 1), exposure: m(0.9, 0.8) });

  it("reports no changes when metrics are equal", () => {
    const d = diffBaseline({ headers: m(1, 1), exposure: m(0.9, 0.8) }, baseline);
    expect(d).toEqual({ regressions: [], improvements: [], newModules: [], missingModules: [] });
  });

  it("flags drops in precision and recall as regressions", () => {
    const d = diffBaseline({ headers: m(0.9, 1), exposure: m(0.9, 0.5) }, baseline);
    expect(d.regressions).toEqual([
      { module: "headers", metric: "precision", baseline: 1, current: 0.9 },
      { module: "exposure", metric: "recall", baseline: 0.8, current: 0.5 },
    ]);
    expect(d.improvements).toEqual([]);
  });

  it("flags rises as improvements, not regressions", () => {
    const d = diffBaseline({ headers: m(1, 1), exposure: m(1, 0.8) }, baseline);
    expect(d.regressions).toEqual([]);
    expect(d.improvements).toEqual([{ module: "exposure", metric: "precision", baseline: 0.9, current: 1 }]);
  });

  it("ignores movement within the tolerance", () => {
    const d = diffBaseline({ headers: m(0.9999, 1), exposure: m(0.9, 0.8) }, baseline, 0.001);
    expect(d.regressions).toEqual([]);
  });

  it("lists new and missing modules", () => {
    const d = diffBaseline({ headers: m(1, 1), tls: m(1, 1) }, baseline);
    expect(d.newModules).toEqual(["tls"]);
    expect(d.missingModules).toEqual(["exposure"]);
  });
});

describe("formatTable", () => {
  const modules = { headers: metricsFor({ tp: 3, fp: 1, fn: 0 }), tls: metricsFor({ tp: 1, fp: 0, fn: 0 }) };

  it("renders one aligned row per module with percentages", () => {
    const table = formatTable(modules);
    const lines = table.split("\n");
    expect(lines).toHaveLength(4);
    expect(lines[0]).toContain("precision");
    expect(lines[2]).toContain("75.0%");
    expect(lines[2]).toContain("100.0%");
    expect(new Set(lines.map((l) => l.length)).size).toBe(1);
  });

  it("shows the change against a baseline", () => {
    const baseline = toBaseline({
      headers: metricsFor({ tp: 3, fp: 0, fn: 0 }),
      tls: metricsFor({ tp: 1, fp: 0, fn: 0 }),
    });
    const table = formatTable({ ...modules, extra: metricsFor({ tp: 1, fp: 0, fn: 0 }) }, baseline);
    expect(table).toMatch(/headers.*worse/);
    expect(table).toMatch(/tls.*=/);
    expect(table).toMatch(/extra.*new/);
  });

  it("marks a module that improved as better", () => {
    const baseline = toBaseline({ headers: metricsFor({ tp: 1, fp: 3, fn: 0 }) });
    expect(formatTable({ headers: modules.headers }, baseline)).toMatch(/headers.*better/);
  });
});

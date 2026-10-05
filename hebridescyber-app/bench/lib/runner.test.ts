import { describe, expect, it, vi } from "vitest";
import type { CorpusTarget } from "../corpus";
import { checkConfiguration, renderReport, runBenchmark, type RunOptions } from "./runner";
import { toBaseline, type Expectation, type ModuleMetrics } from "./scoring";

const SCOPE = ["headers", "exposure"];
const handler = () => undefined;

const corpus: CorpusTarget[] = [
  { id: "a", description: "a", create: () => handler },
  { id: "b", description: "b", create: () => handler },
];

function expectation(target: string, partial: Partial<Expectation> = {}): Expectation {
  return { target, description: "d", mustFind: [], mustNotFind: [], optional: [], knownIssues: [], ...partial };
}

function expectations(): Map<string, Expectation> {
  return new Map([
    ["a", expectation("a", { mustFind: ["headers.x"], mustNotFind: ["exposure.exposed-file:*"] })],
    ["b", expectation("b", { mustFind: ["headers.x"] })],
  ]);
}

const perfect: ModuleMetrics = { tp: 2, fp: 0, fn: 0, precision: 1, recall: 1 };

function options(overrides: Partial<RunOptions> = {}): RunOptions & { closed: string[] } {
  const closed: string[] = [];
  let n = 0;
  return {
    corpus,
    expectations: expectations(),
    scan: async () => ["headers.x"],
    start: async () => {
      const id = `site${n++}`;
      return { url: `http://${id}`, close: async () => void closed.push(id) };
    },
    scope: SCOPE,
    baseline: toBaseline({ headers: perfect }),
    now: () => new Date("2026-01-02T03:04:05.000Z"),
    closed,
    ...overrides,
  };
}

describe("checkConfiguration", () => {
  it("passes when corpus and expectations line up", () => {
    expect(() => checkConfiguration(corpus, expectations())).not.toThrow();
  });

  it("rejects duplicate ids, missing expectations and orphaned expectations", () => {
    expect(() => checkConfiguration([...corpus, corpus[0]], expectations())).toThrow(/Duplicate corpus target id\(s\): a/);
    const missing = expectations();
    missing.delete("b");
    expect(() => checkConfiguration(corpus, missing)).toThrow(/No expectations file for target\(s\): b/);
    const orphan = expectations();
    orphan.set("c", expectation("c"));
    expect(() => checkConfiguration(corpus, orphan)).toThrow(/Expectations without a corpus target: c/);
  });
});

describe("runBenchmark", () => {
  it("passes when everything matches the baseline, closing every site", async () => {
    const o = options();
    const report = await runBenchmark(o);
    expect(report.ok).toBe(true);
    expect(report.problems).toEqual([]);
    expect(report.partial).toBe(false);
    expect(report.generatedAt).toBe("2026-01-02T03:04:05.000Z");
    expect(report.modules.headers).toMatchObject({ tp: 2, precision: 1, recall: 1 });
    expect(o.closed).toEqual(["site0", "site1"]);
  });

  it("uses the real clock when none is injected", async () => {
    const report = await runBenchmark(options({ now: undefined }));
    expect(Number.isNaN(Date.parse(report.generatedAt))).toBe(false);
  });

  it("fails on a forbidden finding", async () => {
    const report = await runBenchmark(options({ scan: async () => ["headers.x", "exposure.exposed-file:/.env"] }));
    expect(report.ok).toBe(false);
    expect(report.problems).toContain("a: forbidden finding exposure.exposed-file:/.env was reported");
  });

  it("fails on a missing finding and on the resulting recall regression", async () => {
    const report = await runBenchmark(options({ scan: async () => [] }));
    expect(report.problems).toContain("a: expected finding headers.x was not reported");
    expect(report.problems.some((p) => p.startsWith("headers: recall regressed from 100.0% to 0.0%"))).toBe(true);
  });

  it("fails on a precision regression from unexpected findings alone", async () => {
    const report = await runBenchmark(options({ scan: async () => ["headers.x", "headers.new"] }));
    // Both targets report the extra finding: 2 TP, 2 FP.
    expect(report.problems).toEqual(["headers: precision regressed from 100.0% to 50.0%"]);
  });

  it("records a scan failure as a problem and still closes the site", async () => {
    const scan = vi.fn().mockRejectedValueOnce(new Error("boom")).mockResolvedValue(["headers.x"]);
    const o = options({ scan });
    const report = await runBenchmark(o);
    expect(report.problems).toContain("a: scan failed (boom)");
    expect(o.closed).toHaveLength(2);
    expect(report.targets).toHaveLength(1);
  });

  it("fails when the baseline is missing", async () => {
    const report = await runBenchmark(options({ baseline: null }));
    expect(report.ok).toBe(false);
    expect(report.problems[0]).toMatch(/No baseline found/);
    expect(report.diff).toBeNull();
  });

  it("fails when a baselined module produced no data", async () => {
    const baseline = toBaseline({ headers: perfect, exposure: perfect });
    const report = await runBenchmark(options({ baseline }));
    expect(report.problems).toContain("exposure: in the baseline but produced no data this run");
  });

  it("runs a subset without comparing against the baseline", async () => {
    const o = options({ only: ["b"], baseline: null });
    const report = await runBenchmark(o);
    expect(report.partial).toBe(true);
    expect(report.ok).toBe(true);
    expect(report.targets.map((t) => t.target)).toEqual(["b"]);
    expect(report.diff).toBeNull();
  });

  it("treats an empty subset as a full run", async () => {
    const report = await runBenchmark(options({ only: [] }));
    expect(report.partial).toBe(false);
  });

  it("rejects an unknown subset target", async () => {
    await expect(runBenchmark(options({ only: ["nope"] }))).rejects.toThrow(/Unknown target\(s\): nope/);
  });

  it("rejects a misconfigured corpus before starting any server", async () => {
    const o = options({ expectations: new Map() });
    const start = vi.fn(o.start);
    await expect(runBenchmark({ ...o, start })).rejects.toThrow(/No expectations file/);
    expect(start).not.toHaveBeenCalled();
  });
});

describe("renderReport", () => {
  it("prints the table and PASS", async () => {
    const baseline = toBaseline({ headers: perfect });
    const report = await runBenchmark(options({ baseline }));
    const text = renderReport(report, baseline);
    expect(text).toContain("precision");
    expect(text).toMatch(/headers.*=/);
    expect(text.trimEnd().endsWith("PASS")).toBe(true);
  });

  it("lists problems under FAIL, plus known, stale and unexpected findings", async () => {
    const known = expectations();
    known.set(
      "a",
      expectation("a", {
        mustFind: ["headers.x"],
        mustNotFind: ["exposure.exposed-file:*"],
        knownIssues: [
          { checkId: "exposure.exposed-file:/old", kind: "false-positive", note: "n" },
          { checkId: "headers.gone", kind: "miss", note: "n" },
        ],
      })
    );
    const baseline = toBaseline({ headers: perfect });
    const report = await runBenchmark(
      options({
        expectations: known,
        baseline,
        scan: async () => ["headers.x", "exposure.exposed-file:/old", "headers.surprise"],
      })
    );
    const text = renderReport(report, baseline);
    expect(text).toContain("FAIL");
    expect(text).toContain("Known issues still reproducing (1): a: exposure.exposed-file:/old");
    expect(text).toContain("Known issues that no longer reproduce");
    expect(text).toContain("a: headers.gone");
    expect(text).toContain("Unexpected findings");
    expect(text).toContain("a: headers.surprise");
    expect(text).toContain("  - headers: precision regressed");
  });

  it("mentions improvements, new modules and partial runs", async () => {
    const worse = toBaseline({ headers: { ...perfect, precision: 0.5 } });
    const improved = await runBenchmark(options({ baseline: worse }));
    expect(renderReport(improved, worse)).toContain("Improved vs baseline");

    const empty = toBaseline({});
    const fresh = await runBenchmark(options({ baseline: empty }));
    expect(renderReport(fresh, empty)).toContain("Modules not in the baseline yet: headers");

    const partial = await runBenchmark(options({ only: ["a"] }));
    expect(renderReport(partial, null)).toContain("Partial run");
  });
});

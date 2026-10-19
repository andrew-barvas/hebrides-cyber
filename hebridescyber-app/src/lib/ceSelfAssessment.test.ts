import { describe, it, expect } from "vitest";
import { CE_CONTROLS, CE_QUESTIONS, combineReadiness, type CeAnswer } from "./ceSelfAssessment";
import type { CeReadinessReport, CeControl, CeControlAssessment } from "./cyberEssentialsReadiness";

/** A scan report where every control carries the given status, no gaps. */
function scanReport(status: CeControlAssessment["status"], gaps: Partial<Record<CeControl, string[]>> = {}): CeReadinessReport {
  return {
    overall_status: "partial",
    score: 0,
    recommendation: "",
    controls: CE_CONTROLS.map((control) => ({
      control,
      status,
      findings: [],
      evidence: [],
      gaps: gaps[control] ?? [],
    })),
  };
}

/** One answer per question with the given value. */
function allAnswers(value: CeAnswer["answer"]): CeAnswer[] {
  return CE_QUESTIONS.map((q) => ({ questionKey: q.key, answer: value }));
}

describe("CE_QUESTIONS catalogue", () => {
  it("has unique keys, each mapped to a real control", () => {
    const keys = CE_QUESTIONS.map((q) => q.key);
    expect(new Set(keys).size).toBe(keys.length);
    for (const q of CE_QUESTIONS) expect(CE_CONTROLS).toContain(q.control);
  });

  it("covers all five controls", () => {
    for (const control of CE_CONTROLS) {
      expect(CE_QUESTIONS.some((q) => q.control === control)).toBe(true);
    }
  });
});

describe("combineReadiness", () => {
  it("is partial with everything unanswered and no scan", () => {
    const report = combineReadiness(null, []);
    expect(report.overall_status).toBe("partial");
    expect(report.answered).toBe(0);
    expect(report.total_questions).toBe(CE_QUESTIONS.length);
    // Every control partial (unanswered questions), none pass.
    expect(report.controls.every((c) => c.status === "partial")).toBe(true);
    expect(report.score).toBe(0);
  });

  it("is ready when scan passes and every answer is satisfied", () => {
    const report = combineReadiness(scanReport("pass"), allAnswers("yes"));
    expect(report.overall_status).toBe("ready");
    expect(report.score).toBe(100);
    expect(report.answered).toBe(CE_QUESTIONS.length);
    expect(report.controls.every((c) => c.status === "pass")).toBe(true);
  });

  it("treats 'na' as satisfied", () => {
    const report = combineReadiness(scanReport("pass"), allAnswers("na"));
    expect(report.overall_status).toBe("ready");
  });

  it("a single 'No' answer fails that control and the overall report", () => {
    const answers = allAnswers("yes");
    const firewallQ = CE_QUESTIONS.find((q) => q.control === "Firewalls and internet gateways")!;
    answers.find((a) => a.questionKey === firewallQ.key)!.answer = "no";
    const report = combineReadiness(scanReport("pass"), answers);
    expect(report.overall_status).toBe("not-ready");
    const firewalls = report.controls.find((c) => c.control === "Firewalls and internet gateways")!;
    expect(firewalls.status).toBe("fail");
    expect(firewalls.gaps.some((g) => g.startsWith('You answered "No"'))).toBe(true);
  });

  it("takes the worse of scan and questionnaire per control", () => {
    // Scan fails one control; answers all satisfied → that control still fails.
    const report = combineReadiness(scanReport("fail"), allAnswers("yes"));
    expect(report.overall_status).toBe("not-ready");
    expect(report.controls.every((c) => c.status === "fail")).toBe(true);
  });

  it("a scan 'not-assessed' is neutral — the questionnaire still decides", () => {
    const report = combineReadiness(scanReport("not-assessed"), allAnswers("yes"));
    expect(report.overall_status).toBe("ready");
  });

  it("surfaces scan gaps with a 'Scan:' prefix", () => {
    const report = combineReadiness(
      scanReport("partial", { "Secure configuration": ["No Content Security Policy"] }),
      allAnswers("yes")
    );
    const config = report.controls.find((c) => c.control === "Secure configuration")!;
    expect(config.gaps).toContain("Scan: No Content Security Policy");
  });

  it("ignores answers whose key isn't in the catalogue", () => {
    const report = combineReadiness(scanReport("pass"), [
      ...allAnswers("yes"),
      { questionKey: "removed.question", answer: "no" },
    ]);
    // The stray "no" must not pull any control to fail.
    expect(report.overall_status).toBe("ready");
    expect(report.answered).toBe(CE_QUESTIONS.length);
  });

  it("a 'partial' answer makes the control partial, not fail", () => {
    const answers = allAnswers("yes");
    answers[0].answer = "partial";
    const report = combineReadiness(scanReport("pass"), answers);
    expect(report.overall_status).toBe("partial");
  });

  it("counts answered questions and prompts to finish when some are blank", () => {
    const half = allAnswers("yes").slice(0, 3);
    const report = combineReadiness(scanReport("pass"), half);
    expect(report.answered).toBe(3);
    expect(report.recommendation).toContain("remaining");
  });
});

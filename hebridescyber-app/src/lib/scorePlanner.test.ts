import { describe, expect, it } from "vitest";
import { ratingFor } from "./executiveReport";
import { scoreFromFindings, type Finding } from "./scanners";
import {
  RATING_TARGETS,
  nextRatingTarget,
  planCandidates,
  planToTarget,
  projectScore,
  projectWithFixes,
  ratingLabel,
  totalPenalty,
  type PlannerFinding,
} from "./scorePlanner";

const f = (checkId: string, severity: string, extra: Partial<PlannerFinding> = {}): PlannerFinding => ({ checkId, severity, title: checkId, ...extra });

describe("rating bands", () => {
  it("match executiveReport's ratingFor at every score", () => {
    for (let s = 0; s <= 100; s++) expect(ratingLabel(s)).toBe(ratingFor(s).label);
  });

  it("list targets highest first", () => {
    expect(RATING_TARGETS.map((t) => t.minScore)).toEqual([90, 75, 50]);
  });

  it("name the next band above a score, or none at Strong", () => {
    expect(nextRatingTarget(30)?.label).toBe("Needs attention");
    expect(nextRatingTarget(50)?.label).toBe("Good");
    expect(nextRatingTarget(89)?.label).toBe("Strong");
    expect(nextRatingTarget(90)).toBeNull();
  });
});

describe("planCandidates", () => {
  it("prices findings with the scoring model and drops zero-point and unkeyed ones", () => {
    const c = planCandidates([f("a", "high"), f("b", "info"), { severity: "critical", title: "no id" }, f("c", "medium", { threatIntel: { knownExploited: true } })]);
    expect(c.map((x) => [x.checkId, x.points])).toEqual([
      ["a", 15],
      ["c", 10.5],
    ]);
  });

  it("orders largest first, then easiest, and keeps one entry per checkId", () => {
    const c = planCandidates([f("hard", "high", { fixDifficulty: "hard" }), f("easy", "high", { fixDifficulty: "trivial" }), f("easy", "high"), f("crit", "critical")]);
    expect(c.map((x) => x.checkId)).toEqual(["crit", "easy", "hard"]);
  });

  it("treats an unknown severity as info (no points), never as serious", () => {
    expect(planCandidates([f("x", "catastrophic")])).toEqual([]);
  });
});

describe("projection", () => {
  it("anchors to the stored score while it is above 0", () => {
    expect(totalPenalty(62, 999)).toBe(38);
    expect(projectScore(62, 38, 15)).toBe(77);
  });

  it("at 0 uses what it can see, at least 100, so it never over-promises", () => {
    expect(totalPenalty(0, 150)).toBe(150);
    expect(totalPenalty(0, 40)).toBe(100);
    expect(projectScore(0, 150, 30)).toBe(0);
    expect(projectScore(0, 150, 60)).toBe(10);
  });

  it("caps at 100", () => {
    expect(projectScore(95, 5, 50)).toBe(100);
  });

  it("matches a real rescore when the stored score came from the same findings", () => {
    const findings: Finding[] = [
      { checkId: "a", severity: "high", title: "a", detail: "" },
      { checkId: "b", severity: "medium", title: "b", detail: "" },
      { checkId: "c", severity: "critical", title: "c", detail: "", threatIntel: { knownExploited: true } },
    ];
    const score = scoreFromFindings(findings);
    const candidates = planCandidates(findings);
    expect(projectWithFixes(score, candidates, ["a"])).toBe(scoreFromFindings(findings.filter((x) => x.checkId !== "a")));
    expect(projectWithFixes(score, candidates, ["a", "c"])).toBe(scoreFromFindings(findings.filter((x) => x.checkId === "b")));
  });
});

describe("planToTarget", () => {
  const findings = [f("crit", "critical"), f("high1", "high", { fixDifficulty: "hard" }), f("high2", "high", { fixDifficulty: "trivial" }), f("med", "medium"), f("low", "low")];
  // 100 - 30 - 15 - 15 - 7 - 2 = 31
  const candidates = planCandidates(findings);

  it("takes the fewest fixes, largest first, preferring the easier of equals", () => {
    const plan = planToTarget(31, candidates, 75);
    expect(plan.fixes.map((x) => x.checkId)).toEqual(["crit", "high2"]);
    expect(plan.projected).toBe(76);
    expect(plan.reachable).toBe(true);
  });

  it("returns no fixes when already there", () => {
    const plan = planToTarget(80, candidates, 75);
    expect(plan.fixes).toEqual([]);
    expect(plan.projected).toBe(80);
  });

  it("says when fixing everything visible still falls short", () => {
    const plan = planToTarget(10, planCandidates([f("only", "high")]), 90);
    expect(plan.reachable).toBe(false);
    expect(plan.projected).toBe(25);
    expect(plan.fixes).toHaveLength(1);
  });

  it("puts a forced finding first and fills the rest largest first", () => {
    const plan = planToTarget(31, candidates, 75, { include: ["low"] });
    expect(plan.fixes.map((x) => x.checkId)).toEqual(["low", "crit", "high2"]);
    expect(plan.projected).toBe(78);
  });

  it("is never fooled by a forced id that isn't a candidate", () => {
    expect(planToTarget(31, candidates, 75, { include: ["nope"] }).fixes.map((x) => x.checkId)).toEqual(["crit", "high2"]);
  });
});

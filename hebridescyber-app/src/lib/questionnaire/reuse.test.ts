import { describe, expect, it } from "vitest";
import { applyReuse, findReusable, questionSimilarity, questionTokens, type PriorAnswer } from "./reuse";
import { NEEDS_YOUR_ANSWER, citationLine, statusLabel, type DraftAnswer } from "./types";

const prior = (over: Partial<PriorAnswer> = {}): PriorAnswer => ({
  id: "p1",
  question: "Do you enforce multi-factor authentication for all staff?",
  topic: "mfa",
  answer: "Yes. MFA is enforced on Microsoft 365 for every account.",
  evidence: [{ source: "m365", label: "Microsoft 365 check", detail: "ok", date: "2026-10-01" }, { source: "previous_answer", label: "older", detail: "x", date: null }],
  decidedAt: "2026-10-02T00:00:00Z",
  questionnaireName: "Insurer renewal 2026.xlsx",
  ...over,
});

const needs: DraftAnswer = { topic: "training", answer: NEEDS_YOUR_ANSWER, evidence: [], confidence: "none", status: "needs_answer", note: "n", reusedFrom: null };

describe("similarity", () => {
  it("ignores stop words, punctuation and simple suffixes", () => {
    expect([...questionTokens("Are the backups tested?")]).toEqual(["backup", "test"]);
    expect(questionSimilarity("Are backups tested?", "Is the backup tested")).toBe(1);
    expect(questionSimilarity("", "Is MFA on?")).toBe(0);
    expect(questionSimilarity("Do you enforce MFA for email?", "Is CCTV installed at premises?")).toBe(0);
  });
});

describe("findReusable", () => {
  it("finds close wording, and fairly close wording on the same topic", () => {
    expect(findReusable("Do you enforce multi-factor authentication for all staff members?", null, [prior()])?.prior.id).toBe("p1");
    expect(findReusable("Is multi-factor authentication enforced for staff?", "mfa", [prior()])?.prior.id).toBe("p1");
    expect(findReusable("Is multi-factor authentication enforced for staff?", "training", [prior()])).toBeNull();
  });

  it("skips empty answers and prefers the closest, then the newest", () => {
    const q = "Do you enforce multi-factor authentication for all staff?";
    expect(findReusable(q, "mfa", [prior({ answer: " " })])).toBeNull();
    const older = prior({ id: "old", decidedAt: "2026-01-01T00:00:00Z" });
    const newer = prior({ id: "new", decidedAt: "2026-11-01T00:00:00Z" });
    expect(findReusable(q, "mfa", [older, newer])?.prior.id).toBe("new");
    expect(findReusable(q, "mfa", [prior({ id: "nodate", decidedAt: null }), older])?.prior.id).toBe("old");
  });
});

describe("applyReuse", () => {
  it("leaves the rule draft alone with nothing similar", () => {
    expect(applyReuse(needs, "Do staff get training?", [prior()])).toBe(needs);
  });

  it("reuses the customer's own accepted answer as a fresh draft, citing where it came from", () => {
    const d = applyReuse({ ...needs, topic: null }, "Do you enforce multi-factor authentication for all staff?", [prior()]);
    expect(d).toMatchObject({ status: "draft", confidence: "medium", reusedFrom: "p1", topic: "mfa", answer: prior().answer });
    expect(d.evidence[0]).toMatchObject({ source: "previous_answer", date: "2026-10-02", label: 'Your accepted answer in "Insurer renewal 2026.xlsx"' });
    expect(d.evidence.filter((e) => e.source === "previous_answer")).toHaveLength(1);
    expect(applyReuse(needs, "Do you enforce multi-factor authentication for all staff?", [prior({ decidedAt: null })]).evidence[0].date).toBeNull();
  });

  it("won't carry a stale Yes over today's evidence of a gap", () => {
    const gap: DraftAnswer = { topic: "mfa", answer: "No, not for every account.", evidence: [], confidence: "high", status: "draft", note: null, reusedFrom: null };
    const d = applyReuse(gap, "Do you enforce multi-factor authentication for all staff?", [prior()]);
    expect(d.answer).toBe(gap.answer);
    expect(d.note).toMatch(/wasn't reused/);
    // An earlier "No" agrees with the gap, so it is reused.
    expect(applyReuse(gap, "Do you enforce multi-factor authentication for all staff?", [prior({ answer: "No. Rolling out by March." })]).reusedFrom).toBe("p1");
  });
});

describe("labels", () => {
  it("labels every status for the export", () => {
    expect(statusLabel("accepted", false)).toBe("Accepted");
    expect(statusLabel("accepted", true)).toBe("Accepted (edited)");
    expect(statusLabel("rejected", false)).toBe("Rejected");
    expect(statusLabel("needs_answer", false)).toBe(NEEDS_YOUR_ANSWER);
    expect(statusLabel("draft", false)).toBe("Draft, not reviewed");
  });
  it("writes a citation on one line", () => {
    expect(citationLine({ source: "scan", label: "Website scan of a", detail: "ok", date: "2026-11-01" })).toBe("Website scan of a (2026-11-01): ok");
    expect(citationLine({ source: "document", label: "Doc", detail: "ok", date: null })).toBe("Doc: ok");
  });
});

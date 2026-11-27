// Reusing the customer's earlier accepted answers. Questionnaires repeat the
// same twenty questions in slightly different words, so an answer a person
// already checked and accepted is the best starting point, as a draft that
// still needs accepting again.
import type { DraftAnswer, EvidenceCitation } from "./types";

export type PriorAnswer = {
  id: string;
  question: string;
  topic: string | null;
  answer: string;
  evidence: EvidenceCitation[];
  decidedAt: string | null;
  questionnaireName: string;
};

const STOP = new Set(
  "a an and are as at be by do does for from has have how i in is it its of on or our that the their there this to we what when where which who will with you your yours any all".split(" "),
);

/** Pure: a question as a set of content words, lightly stemmed. */
export function questionTokens(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, " ")
      .split(/[\s-]+/)
      .filter((w) => w.length > 1 && !STOP.has(w))
      .map((w) => w.replace(/(ing|ed|es|s)$/, "") || w),
  );
}

/** Pure: Jaccard similarity of two questions' content words, 0..1. */
export function questionSimilarity(a: string, b: string): number {
  const x = questionTokens(a);
  const y = questionTokens(b);
  if (!x.size || !y.size) return 0;
  let shared = 0;
  for (const w of x) if (y.has(w)) shared++;
  return shared / (x.size + y.size - shared);
}

/** Similar enough to reuse: close wording, or fairly close wording on the same topic. */
const THRESHOLD_ANY = 0.7;
const THRESHOLD_SAME_TOPIC = 0.5;

/** Pure: the best earlier accepted answer for this question, or null. Ties go to the most recent. */
export function findReusable(question: string, topic: string | null, prior: PriorAnswer[]): { prior: PriorAnswer; similarity: number } | null {
  let best: { prior: PriorAnswer; similarity: number } | null = null;
  for (const p of prior) {
    if (!p.answer.trim()) continue;
    const similarity = questionSimilarity(question, p.question);
    const threshold = topic && p.topic === topic ? THRESHOLD_SAME_TOPIC : THRESHOLD_ANY;
    if (similarity < threshold) continue;
    if (!best || similarity > best.similarity || (similarity === best.similarity && (p.decidedAt ?? "") > (best.prior.decidedAt ?? ""))) best = { prior: p, similarity };
  }
  return best;
}

/**
 * Pure: combine the rule-based draft with an earlier accepted answer. The
 * earlier answer wins, except when today's evidence shows a gap on the same
 * question: then a stale "Yes" must not be carried forward.
 */
export function applyReuse(rule: DraftAnswer, question: string, prior: PriorAnswer[]): DraftAnswer {
  const match = findReusable(question, rule.topic, prior);
  if (!match) return rule;
  const showsGap = rule.status === "draft" && rule.confidence === "high" && /^(no|partly|not)\b/i.test(rule.answer);
  if (showsGap && !/^(no|partly|not)\b/i.test(match.prior.answer)) {
    return { ...rule, note: `Your earlier accepted answer from "${match.prior.questionnaireName}" wasn't reused because the latest evidence shows a gap.` };
  }
  const cite: EvidenceCitation = {
    source: "previous_answer",
    label: `Your accepted answer in "${match.prior.questionnaireName}"`,
    detail: `To a similar question: "${match.prior.question.slice(0, 200)}"`,
    date: match.prior.decidedAt ? match.prior.decidedAt.slice(0, 10) : null,
  };
  return {
    topic: rule.topic ?? match.prior.topic,
    answer: match.prior.answer,
    evidence: [cite, ...match.prior.evidence.filter((e) => e.source !== "previous_answer")].slice(0, 6),
    confidence: "medium",
    status: "draft",
    note: "Reused from an answer you accepted before. Check it still holds.",
    reusedFrom: match.prior.id,
  };
}

// POST /api/questionnaires/[id]/word — optional AI phrasing of the drafted
// answers that are still waiting for review (src/lib/questionnaire/aiWording.ts,
// the app's existing Azure OpenAI deployment). Rewords up to
// MAX_ITEMS_PER_CALL drafts per call; the page calls again while `remaining`
// is above zero. Pro plan and above, session only, rate-limited.
//
// Only evidenced drafts are sent: never a "Needs your answer" row, never an
// answer a person has accepted, edited or rejected, and never a reused answer
// (the customer's own words). The model sees the question, the draft and its
// evidence lines, nothing else.
//   → { worded, remaining, status: "ok" | "not_configured" | "error" }
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { planGate } from "@/lib/planAccess";
import { checkRateLimit } from "@/lib/rateLimit";
import { MAX_ITEMS_PER_CALL, wordAnswers } from "@/lib/questionnaire/aiWording";
import { NOT_ENABLED } from "@/lib/questionnaire/store";
import { citationLine, type EvidenceCitation } from "@/lib/questionnaire/types";

const ROUTE = "questionnaires/[id]/word";
const WORD_POLICY = { max: 120, windowSeconds: 3600 };

type Pending = { id: string; question: string; answer: string; evidence: EvidenceCitation[] };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") return res.status(403).json({ error: "Questionnaires can only be managed from a logged-in session." });

  const id = String(req.query.id ?? "");
  if (!z.string().uuid().safeParse(id).success) return res.status(400).json({ error: "id must be a questionnaire id" });

  const gate = await planGate(supabaseAdmin, caller.ownerId, "pro");
  if (gate === "error") return respondInternalError(res, ROUTE, { message: "plan lookup failed" }, { publicMessage: "Could not check your plan. Try again." });
  if (gate === "denied") return res.status(403).json({ error: "The questionnaire autopilot is on the Pro plan and above.", code: "plan_required" });

  const limit = await checkRateLimit(caller.ownerId, "questionnaire-word", WORD_POLICY);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many requests. Try again later.", retryAfterSeconds: limit.retryAfterSeconds });
  }

  const pendingQuery = () =>
    supabaseAdmin
      .from("questionnaire_answers")
      .select("id, question, answer, evidence", { count: "exact" })
      .eq("questionnaire_id", id)
      .eq("owner", caller.ownerId)
      .eq("status", "draft")
      .eq("ai_checked", false)
      .is("reused_from", null)
      .neq("confidence", "none")
      .order("row_index", { ascending: true })
      .limit(MAX_ITEMS_PER_CALL);

  const { data, count, error } = await pendingQuery();
  if (error) {
    if (isMissingSchemaError(error)) return res.status(503).json({ error: NOT_ENABLED });
    return respondInternalError(res, ROUTE, error);
  }
  const pending = (data ?? []) as Pending[];
  if (!pending.length) return res.status(200).json({ status: "ok", worded: 0, remaining: 0 });

  const result = await wordAnswers(pending.map((p) => ({ id: p.id, question: p.question, draft: p.answer, evidence: (Array.isArray(p.evidence) ? p.evidence : []).map(citationLine) })));
  if (result.status !== "ok") {
    // The rule-based drafts stand; the page says AI wording isn't available.
    if (result.status === "error") console.error(`[${ROUTE}] ${result.message}`);
    return res.status(200).json({ status: result.status, worded: 0, remaining: count ?? pending.length });
  }

  const now = new Date().toISOString();
  for (const p of pending) {
    const text = result.worded.get(p.id);
    // Every item in the batch is marked, worded or not, so a draft the model
    // couldn't improve isn't sent again on the next call.
    const { error: upErr } = await supabaseAdmin
      .from("questionnaire_answers")
      .update(text ? { answer: text, ai_checked: true, ai_worded: true, updated_at: now } : { ai_checked: true, updated_at: now })
      .eq("id", p.id)
      .eq("owner", caller.ownerId)
      .eq("status", "draft");
    if (upErr) return respondInternalError(res, ROUTE, upErr);
  }
  return res.status(200).json({ status: "ok", worded: result.worded.size, remaining: Math.max(0, (count ?? pending.length) - pending.length) });
}

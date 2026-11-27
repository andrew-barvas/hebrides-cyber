// /api/questionnaires/[id] — one questionnaire and its drafted answers.
// Pro plan and above, session only, the caller's own questionnaires.
//   GET    → { questionnaire, answers, counts, aiAvailable }
//   PATCH  { answerIds, action: "accept" | "reject" | "reset" }
//          { answerIds: [one], action: "edit", answer }
//          → { updated, skipped }
//   DELETE → 204
//
// Review is the point of the feature: a drafted answer is only final once a
// person accepts it, and "edit" is accepting your own wording. Accepting an
// answer that is still empty ("Needs your answer") is refused for that row.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { logAuditEvent } from "@/lib/audit";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { planGate } from "@/lib/planAccess";
import { parseBody } from "@/lib/validate";
import { isAiWordingConfigured } from "@/lib/questionnaire/aiWording";
import { loadQuestionnaire, NOT_ENABLED, summarise } from "@/lib/questionnaire/store";

const ROUTE = "questionnaires/[id]";

const patchSchema = z.discriminatedUnion("action", [
  z.object({ action: z.enum(["accept", "reject", "reset"]), answerIds: z.array(z.string().uuid()).min(1).max(5000) }),
  z.object({ action: z.literal("edit"), answerIds: z.array(z.string().uuid()).length(1), answer: z.string().trim().min(1, "answer is required").max(4000) }),
]);

type ReviewRow = { id: string; status: string; answer: string; draft_answer: string; confidence: string };

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "PATCH" && req.method !== "DELETE") {
    res.setHeader("Allow", "GET, PATCH, DELETE");
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

  if (req.method === "GET") {
    const loaded = await loadQuestionnaire(supabaseAdmin, caller.ownerId, id);
    if (!loaded.ok) {
      if (loaded.notFound) return res.status(404).json({ error: "Questionnaire not found" });
      if (isMissingSchemaError(loaded.error as { code?: string })) return res.status(503).json({ error: NOT_ENABLED });
      return respondInternalError(res, ROUTE, loaded.error as { message?: string });
    }
    const { rows, ...meta } = loaded.questionnaire;
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({
      questionnaire: { ...meta, rowCount: Array.isArray(rows) ? rows.length : 0 },
      answers: loaded.answers,
      counts: summarise(loaded.answers),
      aiAvailable: isAiWordingConfigured(),
    });
  }

  if (req.method === "DELETE") {
    const { data, error } = await supabaseAdmin.from("questionnaires").delete().eq("id", id).eq("owner", caller.ownerId).select("id");
    if (error) {
      if (isMissingSchemaError(error)) return res.status(503).json({ error: NOT_ENABLED });
      return respondInternalError(res, ROUTE, error);
    }
    if (!data?.length) return res.status(404).json({ error: "Questionnaire not found" });
    await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "questionnaire.deleted", resourceType: "questionnaire", resourceId: id });
    return res.status(204).end();
  }

  const body = parseBody(patchSchema, req.body, res);
  if (!body) return;

  const { data: found, error: readError } = await supabaseAdmin
    .from("questionnaire_answers")
    .select("id, status, answer, draft_answer, confidence")
    .eq("questionnaire_id", id)
    .eq("owner", caller.ownerId)
    .in("id", body.answerIds);
  if (readError) {
    if (isMissingSchemaError(readError)) return res.status(503).json({ error: NOT_ENABLED });
    return respondInternalError(res, ROUTE, readError);
  }
  const rows = (found ?? []) as ReviewRow[];
  if (!rows.length) return res.status(404).json({ error: "No matching answers in this questionnaire" });

  const now = new Date().toISOString();
  const decided = { decided_by: caller.ownerId, decided_at: now, updated_at: now };
  let updated: string[] = [];
  let skipped: string[] = [];

  const apply = async (ids: string[], patch: Record<string, unknown>) => {
    if (!ids.length) return null;
    const { error } = await supabaseAdmin.from("questionnaire_answers").update(patch).eq("questionnaire_id", id).eq("owner", caller.ownerId).in("id", ids);
    return error;
  };

  let error = null;
  if (body.action === "edit") {
    const row = rows[0];
    error = await apply([row.id], { answer: body.answer, status: "accepted", edited: body.answer !== row.draft_answer, ...decided });
    updated = [row.id];
  } else if (body.action === "accept") {
    // Only an answer with words in it can be accepted; "Needs your answer" needs writing first.
    const ready = rows.filter((r) => r.answer.trim() !== "");
    skipped = rows.filter((r) => r.answer.trim() === "").map((r) => r.id);
    error = await apply(ready.map((r) => r.id), { status: "accepted", ...decided });
    updated = ready.map((r) => r.id);
  } else if (body.action === "reject") {
    error = await apply(rows.map((r) => r.id), { status: "rejected", ...decided });
    updated = rows.map((r) => r.id);
  } else {
    // Back to the draft as first produced.
    const evidenced = rows.filter((r) => r.confidence !== "none");
    const unevidenced = rows.filter((r) => r.confidence === "none");
    error = await apply(evidenced.map((r) => r.id), { status: "draft", edited: false, ai_worded: false, ai_checked: false, decided_by: null, decided_at: null, updated_at: now });
    if (!error) {
      // A reset draft keeps its own text; done per row only for the few that differ.
      for (const r of evidenced.filter((x) => x.answer !== x.draft_answer)) {
        error = await apply([r.id], { answer: r.draft_answer });
        if (error) break;
      }
    }
    if (!error) error = await apply(unevidenced.map((r) => r.id), { status: "needs_answer", answer: "", edited: false, ai_worded: false, ai_checked: false, decided_by: null, decided_at: null, updated_at: now });
    updated = rows.map((r) => r.id);
  }
  if (error) return respondInternalError(res, ROUTE, error);

  await supabaseAdmin.from("questionnaires").update({ updated_at: now }).eq("id", id).eq("owner", caller.ownerId);
  return res.status(200).json({ updated, skipped });
}

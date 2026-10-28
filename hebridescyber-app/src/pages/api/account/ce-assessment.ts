// GET/PUT /api/account/ce-assessment — the Cyber Essentials self-assessment
// answers only the customer can give (ce_self_assessment, migration 061).
//
// GET returns the owner's saved answers. PUT upserts the full answer set (zod-
// validated), one row per question keyed on (owner, question_key). Not plan-
// gated — matches the ce-readiness route and the executive report, which never
// were (see docs/NEXT-STEPS.md's open note on tier-exclusivity).
//
// Before migration 061: GET answers { available: false } so the page can say
// what's missing; PUT returns 503. Evidence discipline — a missing table is
// never silently treated as "no answers saved" for a write.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { parseBody } from "@/lib/validate";
import { CE_QUESTIONS, type CeAnswer } from "@/lib/ceSelfAssessment";

const QUESTION_KEYS = CE_QUESTIONS.map((q) => q.key);
const KEY_TO_CONTROL = new Map(CE_QUESTIONS.map((q) => [q.key, q.control]));

const answerSchema = z.object({
  questionKey: z.enum(QUESTION_KEYS as [string, ...string[]]),
  answer: z.enum(["yes", "no", "partial", "na"]),
  note: z.string().max(1000).nullish(),
});
const putSchema = z.object({
  // Up to one answer per catalogued question; duplicates collapse on upsert.
  answers: z.array(answerSchema).max(CE_QUESTIONS.length),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "PUT") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Unauthorized" });

  if (req.method === "PUT") {
    const parsed = parseBody(putSchema, req.body, res);
    if (!parsed) return;

    const now = new Date().toISOString();
    // De-dupe by questionKey (last wins) so the upsert's ON CONFLICT target
    // never sees two rows with the same (owner, question_key) in one request.
    const byKey = new Map<string, CeAnswer>();
    for (const a of parsed.answers) byKey.set(a.questionKey, a);
    const rows = [...byKey.values()].map((a) => ({
      owner: caller.ownerId,
      control: KEY_TO_CONTROL.get(a.questionKey)!,
      question_key: a.questionKey,
      answer: a.answer,
      note: a.note ?? null,
      updated_at: now,
    }));

    if (rows.length > 0) {
      const { error } = await supabaseAdmin.from("ce_self_assessment").upsert(rows, { onConflict: "owner,question_key" });
      if (error) {
        if (isMissingSchemaError(error)) {
          return res.status(503).json({ error: "The self-assessment isn't enabled on this server yet (database migration 061 pending)." });
        }
        return res.status(500).json({ error: "Could not save the self-assessment answers" });
      }
    }

    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "ce_assessment.saved",
      resourceType: "ce_self_assessment",
      resourceId: caller.ownerId,
      metadata: { answered: rows.length },
    });
    return res.status(200).json({ saved: rows.length });
  }

  const { data, error } = await supabaseAdmin
    .from("ce_self_assessment")
    .select("control, question_key, answer, note, updated_at")
    .eq("owner", caller.ownerId);

  if (error) {
    if (isMissingSchemaError(error)) {
      return res.status(200).json({ available: false, answers: [] });
    }
    return res.status(500).json({ error: "Could not load the self-assessment answers" });
  }

  const answers: CeAnswer[] = (data ?? []).map((r) => ({
    questionKey: r.question_key as string,
    answer: r.answer as CeAnswer["answer"],
    note: (r.note as string | null) ?? null,
  }));
  return res.status(200).json({ available: true, answers });
}

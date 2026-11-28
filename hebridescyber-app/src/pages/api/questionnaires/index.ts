// /api/questionnaires — the security questionnaire autopilot
// (src/lib/questionnaire/, migration 087). Pro plan and above, session only.
//   GET  → { questionnaires, enabled, aiAvailable }
//   POST { fileName, dataUrl, preview: true }
//        → { format, sheets: [{ name, headers, sample, rowCount, suggestedColumn, confident }] }
//   POST { fileName, dataUrl, sheet?, questionColumn }
//        → 201 { id, questions }: saved, with an answer drafted to every question
//
// Answers are drafted from the customer's own evidence only, and nothing is
// final until a person accepts it (PATCH /api/questionnaires/[id]).
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { logAuditEvent } from "@/lib/audit";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { planGate } from "@/lib/planAccess";
import { checkRateLimit } from "@/lib/rateLimit";
import { parseBody } from "@/lib/validate";
import { isAiWordingConfigured } from "@/lib/questionnaire/aiWording";
import { decodeUpload, detectQuestionColumn, formatFromName, parseQuestionnaire, questionRows, MAX_COLUMNS } from "@/lib/questionnaire/spreadsheet";
import { createQuestionnaire, MAX_QUESTIONNAIRES, NOT_ENABLED, summarise } from "@/lib/questionnaire/store";
import type { AnswerStatus } from "@/lib/questionnaire/types";

const ROUTE = "questionnaires";
// Uploads are expensive (a parse and an evidence load each), so a deliberate-action limit.
const UPLOAD_POLICY = { max: 30, windowSeconds: 3600 };

export const config = { api: { bodyParser: { sizeLimit: "7mb" } } };

const uploadSchema = z.object({
  fileName: z.string().trim().min(1).max(200),
  dataUrl: z.string().min(1),
  preview: z.boolean().optional(),
  sheet: z.string().max(100).nullable().optional(),
  questionColumn: z.number().int().min(0).max(MAX_COLUMNS - 1).optional(),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") return res.status(403).json({ error: "Questionnaires can only be managed from a logged-in session." });

  const gate = await planGate(supabaseAdmin, caller.ownerId, "pro");
  if (gate === "error") return respondInternalError(res, ROUTE, { message: "plan lookup failed" }, { publicMessage: "Could not check your plan. Try again." });
  if (gate === "denied") return res.status(403).json({ error: "The questionnaire autopilot is on the Pro plan and above.", code: "plan_required" });

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin
      .from("questionnaires")
      .select("id, name, source_format, created_at, updated_at, questionnaire_answers(status)")
      .eq("owner", caller.ownerId)
      .order("created_at", { ascending: false })
      .limit(MAX_QUESTIONNAIRES);
    if (error) {
      if (isMissingSchemaError(error)) return res.status(200).json({ questionnaires: [], enabled: false, aiAvailable: false });
      return respondInternalError(res, ROUTE, error);
    }
    const questionnaires = ((data ?? []) as Array<{ id: string; name: string; source_format: string; created_at: string; updated_at: string; questionnaire_answers: Array<{ status: AnswerStatus }> | null }>).map(
      ({ questionnaire_answers, ...q }) => ({ ...q, counts: summarise(questionnaire_answers ?? []) }),
    );
    return res.status(200).json({ questionnaires, enabled: true, aiAvailable: isAiWordingConfigured() });
  }

  const body = parseBody(uploadSchema, req.body, res);
  if (!body) return;
  const format = formatFromName(body.fileName);
  if (!format) return res.status(400).json({ error: "Upload an .xlsx or .csv file." });

  const limit = await checkRateLimit(caller.ownerId, "questionnaire-upload", UPLOAD_POLICY);
  if (!limit.allowed) {
    res.setHeader("Retry-After", String(limit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many uploads. Try again later.", retryAfterSeconds: limit.retryAfterSeconds });
  }

  const decoded = decodeUpload(body.dataUrl);
  if (!decoded.ok) return res.status(400).json({ error: decoded.error });
  const parsed = await parseQuestionnaire(decoded.bytes, format);
  if (!parsed.ok) return res.status(400).json({ error: parsed.error });

  if (body.preview || body.questionColumn === undefined) {
    return res.status(200).json({
      format,
      sheets: parsed.sheets.map((s) => {
        const guess = detectQuestionColumn(s);
        return { name: s.name, headers: s.headers, sample: s.rows.slice(0, 5), rowCount: s.rows.length, suggestedColumn: guess.column, confident: guess.confident, questions: questionRows(s.rows, guess.column).length };
      }),
    });
  }

  const table = body.sheet ? parsed.sheets.find((s) => s.name === body.sheet) : parsed.sheets[0];
  if (!table) return res.status(400).json({ error: "That sheet wasn't found in the file." });
  if (body.questionColumn >= table.headers.length) return res.status(400).json({ error: "That column isn't in the sheet." });

  const { count, error: countError } = await supabaseAdmin.from("questionnaires").select("id", { count: "exact", head: true }).eq("owner", caller.ownerId);
  if (countError) {
    if (isMissingSchemaError(countError)) return res.status(503).json({ error: NOT_ENABLED });
    return respondInternalError(res, ROUTE, countError);
  }
  if ((count ?? 0) >= MAX_QUESTIONNAIRES) return res.status(409).json({ error: `You can keep up to ${MAX_QUESTIONNAIRES} questionnaires. Delete an old one first.` });

  const created = await createQuestionnaire(supabaseAdmin, caller.ownerId, { name: body.fileName, format, table, questionColumn: body.questionColumn });
  if (!created.ok) {
    if (created.status === 500) return respondInternalError(res, ROUTE, (created.cause as { message?: string; code?: string } | undefined) ?? new Error(created.error), { publicMessage: created.error });
    return res.status(created.status).json({ error: created.error });
  }

  await logAuditEvent(supabaseAdmin, {
    actorId: caller.ownerId,
    action: "questionnaire.created",
    resourceType: "questionnaire",
    resourceId: created.id,
    metadata: { format, questions: created.questions },
  });
  return res.status(201).json({ id: created.id, questions: created.questions });
}

// GET /api/questionnaires/[id]/export?format=xlsx|csv — the questionnaire's
// original rows with Answer, Evidence and Status columns appended, and a
// closing line saying the answers are drafts based on scan evidence, not
// certification. Pro plan and above, session only, the caller's own.
// Unreviewed drafts are exported with the status "Draft, not reviewed".
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { respondInternalError } from "@/lib/apiError";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { planGate } from "@/lib/planAccess";
import { buildExport, loadQuestionnaire, NOT_ENABLED } from "@/lib/questionnaire/store";

const ROUTE = "questionnaires/[id]/export";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") return res.status(403).json({ error: "Questionnaires can only be managed from a logged-in session." });

  const id = String(req.query.id ?? "");
  if (!z.string().uuid().safeParse(id).success) return res.status(400).json({ error: "id must be a questionnaire id" });
  const format = req.query.format === "csv" ? "csv" : req.query.format === undefined || req.query.format === "xlsx" ? "xlsx" : null;
  if (!format) return res.status(400).json({ error: "format must be xlsx or csv" });

  const gate = await planGate(supabaseAdmin, caller.ownerId, "pro");
  if (gate === "error") return respondInternalError(res, ROUTE, { message: "plan lookup failed" }, { publicMessage: "Could not check your plan. Try again." });
  if (gate === "denied") return res.status(403).json({ error: "The questionnaire autopilot is on the Pro plan and above.", code: "plan_required" });

  const loaded = await loadQuestionnaire(supabaseAdmin, caller.ownerId, id);
  if (!loaded.ok) {
    if (loaded.notFound) return res.status(404).json({ error: "Questionnaire not found" });
    if (isMissingSchemaError(loaded.error as { code?: string })) return res.status(503).json({ error: NOT_ENABLED });
    return respondInternalError(res, ROUTE, loaded.error as { message?: string });
  }

  let file: Awaited<ReturnType<typeof buildExport>>;
  try {
    file = await buildExport(loaded.questionnaire, loaded.answers, format);
  } catch (err) {
    return respondInternalError(res, ROUTE, err as Error, { publicMessage: "Couldn't build the export. Try again." });
  }
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", file.contentType);
  res.setHeader("Content-Disposition", `attachment; filename="${file.fileName.replace(/"/g, "")}"`);
  return res.status(200).send(file.body);
}

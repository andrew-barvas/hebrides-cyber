// /api/account/custom-checks: a customer's own nuclei checks (Agency and Tier A).
//
//   GET     list this account's checks (id, name, severity, enabled, yaml)
//   POST    { yaml }  validate and save one check
//   PATCH   { id, enabled }  switch one on or off
//   DELETE  { id }
//
// Session-only, like API keys: a check runs inside our scan worker, so an
// automation credential must not be able to add one. Writes go through the
// service role (the table is read-only to the browser) and ONLY after
// validateCustomTemplate() passes; the same validator runs again before every
// scan (src/worker/tools/customNuclei.ts).
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { validateCustomTemplate, MAX_TEMPLATES_PER_OWNER, MAX_TEMPLATE_BYTES } from "@/lib/customNucleiTemplates";
import { planGate } from "@/lib/planAccess";
import { parseBody } from "@/lib/validate";

const createSchema = z.object({ yaml: z.string().min(1, "yaml is required").max(MAX_TEMPLATE_BYTES * 2, "template is too large") });
const patchSchema = z.object({ id: z.string().uuid("id must be a valid UUID"), enabled: z.boolean() });
const deleteSchema = z.object({ id: z.string().uuid("id must be a valid UUID") });

const COLUMNS = "id, template_id, name, severity, enabled, yaml, created_at, updated_at";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (!["GET", "POST", "PATCH", "DELETE"].includes(req.method ?? "")) return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") return res.status(403).json({ error: "Custom checks can only be managed from a logged-in session, not with an API key." });

  const gate = await planGate(supabaseAdmin, caller.ownerId, "agency");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan. Please try again." });
  if (gate === "denied") return res.status(403).json({ error: "Custom checks are part of the Agency plan." });

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin.from("custom_nuclei_templates").select(COLUMNS).eq("owner", caller.ownerId).order("created_at", { ascending: true });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ checks: data ?? [], limit: MAX_TEMPLATES_PER_OWNER });
  }

  if (req.method === "DELETE") {
    const parsed = parseBody(deleteSchema, req.body, res);
    if (!parsed) return;
    const { error } = await supabaseAdmin.from("custom_nuclei_templates").delete().eq("id", parsed.id).eq("owner", caller.ownerId);
    if (error) return res.status(500).json({ error: error.message });
    await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "custom_check.deleted", resourceType: "custom_check", resourceId: parsed.id });
    return res.status(200).json({ ok: true });
  }

  if (req.method === "PATCH") {
    const parsed = parseBody(patchSchema, req.body, res);
    if (!parsed) return;
    const { data, error } = await supabaseAdmin
      .from("custom_nuclei_templates")
      .update({ enabled: parsed.enabled, updated_at: new Date().toISOString() })
      .eq("id", parsed.id)
      .eq("owner", caller.ownerId)
      .select(COLUMNS)
      .maybeSingle();
    if (error) return res.status(500).json({ error: error.message });
    if (!data) return res.status(404).json({ error: "Check not found" });
    return res.status(200).json({ check: data });
  }

  const parsed = parseBody(createSchema, req.body, res);
  if (!parsed) return;

  const check = validateCustomTemplate(parsed.yaml);
  if (!check.ok) return res.status(422).json({ error: "This check can't be saved.", problems: check.errors });

  const { count, error: countError } = await supabaseAdmin.from("custom_nuclei_templates").select("id", { count: "exact", head: true }).eq("owner", caller.ownerId);
  if (countError) return res.status(500).json({ error: countError.message });
  if ((count ?? 0) >= MAX_TEMPLATES_PER_OWNER) return res.status(409).json({ error: `You can keep ${MAX_TEMPLATES_PER_OWNER} custom checks. Delete one to add another.` });

  const { data, error } = await supabaseAdmin
    .from("custom_nuclei_templates")
    .insert({ owner: caller.ownerId, template_id: check.id, name: check.name, severity: check.severity, yaml: parsed.yaml })
    .select(COLUMNS)
    .single();
  if (error) {
    if (error.code === "23505") return res.status(409).json({ error: `You already have a check with the id "${check.id}".` });
    return res.status(500).json({ error: error.message });
  }
  await logAuditEvent(supabaseAdmin, { actorId: caller.ownerId, action: "custom_check.created", resourceType: "custom_check", resourceId: data.id, metadata: { template_id: check.id, severity: check.severity } });
  return res.status(201).json({ check: data });
}

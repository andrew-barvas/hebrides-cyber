import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { parseBody } from "@/lib/validate";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { planGate } from "@/lib/planAccess";

// "pdf" (the default here and in migration 032) is attached as a real PDF by
// send-scheduled-reports.ts; CSV and JSON go inline in the email body.
const createSchema = z.object({
  targetUrl: z.string().url().nullable().default(null),
  frequency: z.enum(["daily", "weekly", "monthly"]),
  format: z.enum(["pdf", "csv", "json"]).default("pdf"),
  recipients: z.array(z.string().email()).min(1),
});

const updateSchema = z.object({
  id: z.string().uuid(),
  enabled: z.boolean().optional(),
  frequency: z.enum(["daily", "weekly", "monthly"]).optional(),
  format: z.enum(["pdf", "csv", "json"]).optional(),
  recipients: z.array(z.string().email()).min(1).optional(),
});

const deleteSchema = z.object({
  id: z.string().uuid(),
});

// Scheduled reports are a paid-plan feature. The dashboard hides the card
// below a paid plan, but the API is open to any signed-in or keyed caller, so
// the gate has to be here too. Creating or editing needs an active paid plan;
// reading, deleting and pausing don't, so a lapsed account can still see and
// clear what it set up (the sender skips a lapsed owner's reports anyway).
async function requirePaidPlan(ownerId: string, res: NextApiResponse): Promise<boolean> {
  const gate = await planGate(supabaseAdmin, ownerId, "basic");
  if (gate === "ok") return true;
  if (gate === "error") res.status(500).json({ error: "Could not check your plan — try again." });
  else res.status(403).json({ error: "Scheduled reports are part of the paid plans.", code: "plan_required" });
  return false;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin
      .from("scheduled_reports")
      .select("*")
      .eq("owner", caller.ownerId)
      .order("created_at", { ascending: false });

    // Migration 032 not applied to this database yet — degrade to "no
    // reports" rather than 500ing the Dashboard for every paid-plan
    // account on every load.
    if (error && !isMissingSchemaError(error)) {
      return res.status(500).json({ error: error.message });
    }
    return res.status(200).json({ reports: isMissingSchemaError(error) ? [] : data });
  }

  if (req.method === "POST") {
    const body = parseBody(createSchema, req.body, res);
    if (!body) return;
    if (!(await requirePaidPlan(caller.ownerId, res))) return;

    const { data, error } = await supabaseAdmin
      .from("scheduled_reports")
      .insert({
        owner: caller.ownerId,
        target_url: body.targetUrl,
        frequency: body.frequency,
        format: body.format,
        recipients: body.recipients,
        next_due: new Date().toISOString(),
      })
      .select()
      .single();

    if (error) {
      if (isMissingSchemaError(error)) {
        return res.status(503).json({ error: "Scheduled reports aren't available on this account yet — try again shortly." });
      }
      return res.status(500).json({ error: error.message });
    }
    return res.status(201).json(data);
  }

  if (req.method === "PATCH") {
    const body = parseBody(updateSchema, req.body, res);
    if (!body) return;
    const pausingOnly = body.enabled === false && !body.frequency && !body.format && !body.recipients;
    if (!pausingOnly && !(await requirePaidPlan(caller.ownerId, res))) return;

    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
    if (body.enabled !== undefined) updates.enabled = body.enabled;
    if (body.frequency) updates.frequency = body.frequency;
    if (body.format) updates.format = body.format;
    if (body.recipients) updates.recipients = body.recipients;

    const { error } = await supabaseAdmin
      .from("scheduled_reports")
      .update(updates)
      .eq("id", body.id)
      .eq("owner", caller.ownerId);

    if (error) {
      if (isMissingSchemaError(error)) {
        return res.status(503).json({ error: "Scheduled reports aren't available on this account yet — try again shortly." });
      }
      return res.status(500).json({ error: error.message });
    }
    return res.status(200).json({ ok: true });
  }

  if (req.method === "DELETE") {
    const body = parseBody(deleteSchema, req.body, res);
    if (!body) return;

    const { error } = await supabaseAdmin
      .from("scheduled_reports")
      .delete()
      .eq("id", body.id)
      .eq("owner", caller.ownerId);

    if (error) {
      if (isMissingSchemaError(error)) {
        return res.status(503).json({ error: "Scheduled reports aren't available on this account yet — try again shortly." });
      }
      return res.status(500).json({ error: error.message });
    }
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: "Method not allowed" });
}

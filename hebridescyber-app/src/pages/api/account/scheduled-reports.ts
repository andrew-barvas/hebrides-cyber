import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { parseBody } from "@/lib/validate";

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

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin
      .from("scheduled_reports")
      .select("*")
      .eq("owner", caller.ownerId)
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ reports: data });
  }

  if (req.method === "POST") {
    const body = parseBody(createSchema, req.body, res);
    if (!body) return;

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

    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json(data);
  }

  if (req.method === "PATCH") {
    const body = parseBody(updateSchema, req.body, res);
    if (!body) return;

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

    if (error) return res.status(500).json({ error: error.message });
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

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: "Method not allowed" });
}

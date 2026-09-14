import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { parseBody } from "@/lib/validate";
import { validateSiemWebhook } from "@/lib/siemIntegration";
import { logAuditEvent } from "@/lib/audit";

const createSchema = z.object({
  name: z.string().min(1).max(100).default("Default SIEM"),
  type: z.enum(["webhook", "syslog"]),
  endpoint: z.string().min(1),
  authHeader: z.string().nullable().default(null),
  format: z.enum(["json", "cef", "leef"]).default("json"),
  eventTypes: z.array(z.string()).min(1).default(["scan.completed", "finding.new", "finding.fixed"]),
});

const updateSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(100).optional(),
  enabled: z.boolean().optional(),
  endpoint: z.string().min(1).optional(),
  authHeader: z.string().nullable().optional(),
  format: z.enum(["json", "cef", "leef"]).optional(),
  eventTypes: z.array(z.string()).min(1).optional(),
});

const deleteSchema = z.object({
  id: z.string().uuid(),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin
      .from("siem_integrations")
      .select("id, name, type, endpoint, format, event_types, enabled, last_sent, last_error, created_at")
      .eq("owner", caller.ownerId)
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ integrations: data });
  }

  if (req.method === "POST") {
    const body = parseBody(createSchema, req.body, res);
    if (!body) return;

    if (body.type === "webhook") {
      const validation = await validateSiemWebhook(body.endpoint, body.authHeader, body.format);
      if (!validation.ok) {
        return res.status(400).json({ error: `Webhook validation failed: ${validation.error}` });
      }
    }

    const { data, error } = await supabaseAdmin
      .from("siem_integrations")
      .insert({
        owner: caller.ownerId,
        name: body.name,
        type: body.type,
        endpoint: body.endpoint,
        auth_header: body.authHeader,
        format: body.format,
        event_types: body.eventTypes,
      })
      .select()
      .single();

    if (error) return res.status(500).json({ error: error.message });

    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "siem_integration.created",
      resourceType: "siem_integration",
      resourceId: data.id,
      metadata: { type: body.type, endpoint: body.endpoint },
    });

    return res.status(201).json(data);
  }

  if (req.method === "PATCH") {
    const body = parseBody(updateSchema, req.body, res);
    if (!body) return;

    const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
    if (body.name !== undefined) updates.name = body.name;
    if (body.enabled !== undefined) updates.enabled = body.enabled;
    if (body.endpoint !== undefined) updates.endpoint = body.endpoint;
    if (body.authHeader !== undefined) updates.auth_header = body.authHeader;
    if (body.format !== undefined) updates.format = body.format;
    if (body.eventTypes !== undefined) updates.event_types = body.eventTypes;

    const { error } = await supabaseAdmin
      .from("siem_integrations")
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
      .from("siem_integrations")
      .delete()
      .eq("id", body.id)
      .eq("owner", caller.ownerId);

    if (error) return res.status(500).json({ error: error.message });

    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "siem_integration.deleted",
      resourceType: "siem_integration",
      resourceId: body.id,
    });

    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: "Method not allowed" });
}

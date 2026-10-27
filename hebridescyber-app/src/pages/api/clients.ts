// Agency client workspaces — GET (list with site counts), POST (create),
// PATCH (rename / notes / brand override), DELETE.
//
// Session-only like api/keys.ts: client management is an account control, not
// something a CI key should do. Agency-gated; deleting a client never deletes
// its sites (migration 063 sets their client_id to null = "Unassigned").
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { hasAgencyAccess } from "@/lib/planAccess";
import { parseBody } from "@/lib/validate";

const MAX_CLIENTS = 100;

const nameField = z.string().trim().min(1, "name is required").max(80, "name must be 80 characters or fewer");
const optionalText = (max: number) => z.string().trim().max(max, `must be ${max} characters or fewer`).nullable().optional();
const logoField = z.string().trim().max(500).refine((v) => v === "" || /^https:\/\//i.test(v), "must be an https:// URL").nullable().optional();

const createSchema = z.object({
  name: nameField,
  notes: optionalText(2000),
  brand_name: optionalText(80),
  brand_logo_url: logoField,
});

const updateSchema = z.object({
  id: z.string().min(1, "id is required"),
  name: nameField.optional(),
  notes: optionalText(2000),
  brand_name: optionalText(80),
  brand_logo_url: logoField,
});

const deleteSchema = z.object({ id: z.string().min(1, "id is required") });

type ClientRow = {
  id: string;
  name: string;
  notes: string | null;
  brand_name: string | null;
  brand_logo_url: string | null;
  created_at: string;
};

const COLUMNS = "id, name, notes, brand_name, brand_logo_url, created_at";

/** Blank strings from a form mean "clear the override". */
const blankToNull = (v: string | null | undefined) => (v === undefined ? undefined : v && v.length > 0 ? v : null);

function writeError(res: NextApiResponse, error: { code?: string; message: string }) {
  if (isMissingSchemaError(error)) {
    return res.status(503).json({ error: "Client workspaces aren't enabled on this server yet (database migration 063 pending)." });
  }
  if (error.code === "23505") return res.status(409).json({ error: "You already have a client with that name." });
  return res.status(500).json({ error: error.message });
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  if (caller.via !== "session") {
    return res.status(403).json({ error: "Clients can only be managed from a logged-in session, not with an API key." });
  }
  if (!["GET", "POST", "PATCH", "DELETE"].includes(req.method ?? "")) {
    return res.status(405).json({ error: "Method not allowed" });
  }

  if (!(await hasAgencyAccess(supabaseAdmin, caller.ownerId))) {
    return res.status(403).json({ error: "Client workspaces are part of the Agency plan." });
  }

  if (req.method === "GET") {
    const [clientsRes, sitesRes] = await Promise.all([
      supabaseAdmin.from("clients").select(COLUMNS).eq("owner", caller.ownerId).order("name", { ascending: true }),
      supabaseAdmin.from("monitored_targets").select("client_id").eq("owner", caller.ownerId),
    ]);
    if (clientsRes.error) return writeError(res, clientsRes.error);
    if (sitesRes.error) return writeError(res, sitesRes.error);

    const counts = new Map<string, number>();
    let unassigned = 0;
    for (const s of (sitesRes.data ?? []) as { client_id: string | null }[]) {
      if (s.client_id) counts.set(s.client_id, (counts.get(s.client_id) ?? 0) + 1);
      else unassigned += 1;
    }
    const clients = ((clientsRes.data ?? []) as ClientRow[]).map((c) => ({ ...c, site_count: counts.get(c.id) ?? 0 }));
    return res.status(200).json({ clients, unassigned_sites: unassigned });
  }

  if (req.method === "POST") {
    const parsed = parseBody(createSchema, req.body, res);
    if (!parsed) return;

    const { count, error: countError } = await supabaseAdmin
      .from("clients")
      .select("id", { count: "exact", head: true })
      .eq("owner", caller.ownerId);
    if (countError) return writeError(res, countError);
    if ((count ?? 0) >= MAX_CLIENTS) {
      return res.status(400).json({ error: `Client limit reached (${MAX_CLIENTS}). Delete an unused client first.` });
    }

    const { data, error } = await supabaseAdmin
      .from("clients")
      .insert({
        owner: caller.ownerId,
        name: parsed.name,
        notes: blankToNull(parsed.notes) ?? null,
        brand_name: blankToNull(parsed.brand_name) ?? null,
        brand_logo_url: blankToNull(parsed.brand_logo_url) ?? null,
      })
      .select(COLUMNS)
      .single();
    if (error || !data) return writeError(res, error ?? { message: "Could not create client" });

    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "client.created",
      resourceType: "client",
      resourceId: data.id,
      metadata: { name: parsed.name },
    });
    return res.status(201).json({ ...data, site_count: 0 });
  }

  if (req.method === "PATCH") {
    const parsed = parseBody(updateSchema, req.body, res);
    if (!parsed) return;

    const patch: Record<string, unknown> = {};
    if (parsed.name !== undefined) patch.name = parsed.name;
    if (parsed.notes !== undefined) patch.notes = blankToNull(parsed.notes);
    if (parsed.brand_name !== undefined) patch.brand_name = blankToNull(parsed.brand_name);
    if (parsed.brand_logo_url !== undefined) patch.brand_logo_url = blankToNull(parsed.brand_logo_url);
    if (Object.keys(patch).length === 0) return res.status(400).json({ error: "body: nothing to update" });

    const { data, error } = await supabaseAdmin
      .from("clients")
      .update(patch)
      .eq("id", parsed.id)
      .eq("owner", caller.ownerId)
      .select(COLUMNS)
      .maybeSingle();
    if (error) return writeError(res, error);
    if (!data) return res.status(404).json({ error: "Client not found" });

    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "client.updated",
      resourceType: "client",
      resourceId: parsed.id,
      metadata: { fields: Object.keys(patch) },
    });
    return res.status(200).json(data);
  }

  // DELETE
  const parsed = parseBody(deleteSchema, req.body, res);
  if (!parsed) return;

  const { data, error } = await supabaseAdmin
    .from("clients")
    .delete()
    .eq("id", parsed.id)
    .eq("owner", caller.ownerId)
    .select("id, name")
    .maybeSingle();
  if (error) return writeError(res, error);
  if (!data) return res.status(404).json({ error: "Client not found" });

  await logAuditEvent(supabaseAdmin, {
    actorId: caller.ownerId,
    action: "client.deleted",
    resourceType: "client",
    resourceId: parsed.id,
    metadata: { name: (data as { name: string }).name },
  });
  return res.status(200).json({ ok: true });
}

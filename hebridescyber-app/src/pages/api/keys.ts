// API key management — GET (list), POST (create), DELETE (revoke).
//
// Deliberately session-only: authenticating here with an API key is rejected.
// A key that can mint further keys turns one leaked CI secret into permanent
// account access that outlives revoking the original.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { mintApiKey } from "@/lib/apiKeys";
import { logAuditEvent } from "@/lib/audit";
import { parseBody } from "@/lib/validate";

const createSchema = z.object({
  name: z.string().min(1, "name is required").max(60, "name must be 60 characters or fewer"),
});

const deleteSchema = z.object({
  id: z.string().min(1, "id is required"),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  if (caller.via !== "session") {
    return res.status(403).json({ error: "API keys can only be managed from a logged-in session, not with an API key." });
  }

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin
      .from("api_keys")
      .select("id, name, key_prefix, last_used_at, revoked_at, created_at")
      .eq("owner", caller.ownerId)
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ keys: data ?? [] });
  }

  if (req.method === "POST") {
    const parsed = parseBody(createSchema, req.body, res);
    if (!parsed) return;
    const keyName = parsed.name.trim();
    if (!keyName) return res.status(400).json({ error: "name is required" });

    const { data: existing } = await supabaseAdmin
      .from("api_keys")
      .select("id")
      .eq("owner", caller.ownerId)
      .is("revoked_at", null);

    if ((existing?.length ?? 0) >= 20) {
      return res.status(400).json({ error: "Key limit reached (20 active). Revoke an unused key first." });
    }

    const minted = mintApiKey();
    const { data, error } = await supabaseAdmin
      .from("api_keys")
      .insert({
        owner: caller.ownerId,
        name: keyName,
        key_hash: minted.key_hash,
        key_prefix: minted.key_prefix,
      })
      .select("id, name, key_prefix, created_at")
      .single();

    if (error) return res.status(500).json({ error: error.message });

    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "api_key.created",
      resourceType: "api_key",
      resourceId: data.id,
      metadata: { name: keyName, key_prefix: data.key_prefix },
    });

    // The only time the plaintext is ever returned. It is not stored, so it
    // cannot be shown again — the UI must make that clear to the user.
    return res.status(201).json({ ...data, key: minted.plaintext });
  }

  if (req.method === "DELETE") {
    const parsed = parseBody(deleteSchema, req.body, res);
    if (!parsed) return;
    const { id } = parsed;

    // Revoke rather than delete: last_used_at stays available as an audit
    // trail of what the key did before it was turned off.
    const { error } = await supabaseAdmin
      .from("api_keys")
      .update({ revoked_at: new Date().toISOString() })
      .eq("id", id)
      .eq("owner", caller.ownerId);

    if (error) return res.status(500).json({ error: error.message });

    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "api_key.revoked",
      resourceType: "api_key",
      resourceId: id,
    });

    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: "Method not allowed" });
}

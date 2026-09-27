// API key management — GET (list), POST (create), PATCH (set a key's IP
// allowlist), DELETE (revoke).
//
// Deliberately session-only: authenticating here with an API key is rejected.
// A key that can mint further keys turns one leaked CI secret into permanent
// account access that outlives revoking the original — and a key that could
// edit its own allowlist could simply remove it.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { mintApiKey } from "@/lib/apiKeys";
import { logAuditEvent } from "@/lib/audit";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { validateAllowlist } from "@/lib/ipAllowlist";
import { parseBody } from "@/lib/validate";

const createSchema = z.object({
  name: z.string().min(1, "name is required").max(60, "name must be 60 characters or fewer"),
});

const deleteSchema = z.object({
  id: z.string().min(1, "id is required"),
});

// Loose shape check only; validateAllowlist() owns the real rules.
const allowlistSchema = z.object({
  id: z.string().min(1, "id is required"),
  allowed_cidrs: z.array(z.string().max(64, "each entry must be 64 characters or fewer")).max(100),
});

type ApiKeyRow = {
  id: string;
  name: string;
  key_prefix: string;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
  allowed_cidrs?: string[];
  last_blocked_ip?: string | null;
  last_blocked_at?: string | null;
};

/** The client-facing shape — never key_hash. The allowlist columns arrive
 *  with migration 042, so they're read defensively. */
function toClientKey(row: ApiKeyRow) {
  return {
    id: row.id,
    name: row.name,
    key_prefix: row.key_prefix,
    last_used_at: row.last_used_at,
    revoked_at: row.revoked_at,
    created_at: row.created_at,
    allowed_cidrs: Array.isArray(row.allowed_cidrs) ? row.allowed_cidrs : [],
    last_blocked_ip: row.last_blocked_ip ?? null,
    last_blocked_at: row.last_blocked_at ?? null,
  };
}


export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  if (caller.via !== "session") {
    return res.status(403).json({ error: "API keys can only be managed from a logged-in session, not with an API key." });
  }

  if (req.method === "GET") {
    // "*" so this works before and after migration 042; toClientKey() drops key_hash.
    const { data, error } = await supabaseAdmin
      .from("api_keys")
      .select("*")
      .eq("owner", caller.ownerId)
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ keys: ((data ?? []) as ApiKeyRow[]).map(toClientKey) });
  }

  if (req.method === "PATCH") {
    const parsed = parseBody(allowlistSchema, req.body, res);
    if (!parsed) return;
    const validation = validateAllowlist(parsed.allowed_cidrs);
    if (!validation.ok) return res.status(400).json({ error: validation.error });

    const { data, error } = await supabaseAdmin
      .from("api_keys")
      .update({ allowed_cidrs: validation.cidrs })
      .eq("id", parsed.id)
      .eq("owner", caller.ownerId)
      .is("revoked_at", null)
      .select("id")
      .maybeSingle();

    if (error) {
      if (isMissingSchemaError(error)) {
        return res.status(503).json({ error: "IP allowlists aren't enabled on this server yet (database migration 042 pending)." });
      }
      return res.status(500).json({ error: error.message });
    }
    if (!data) return res.status(404).json({ error: "Key not found" });

    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "api_key.allowlist_updated",
      resourceType: "api_key",
      resourceId: parsed.id,
      metadata: { allowed_cidrs: validation.cidrs },
    });

    return res.status(200).json({ id: parsed.id, allowed_cidrs: validation.cidrs });
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

// Device management for the patch-audit agent: GET (list with each device's
// latest 14-day evaluation), POST (add a device and issue its token, shown
// once), DELETE (revoke a device's token).
//
// Session-only, like /api/keys: an API key that could mint device tokens
// would turn one leaked CI secret into a way to plant fake devices.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { logAuditEvent } from "@/lib/audit";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { parseBody } from "@/lib/validate";
import { respondInternalError } from "@/lib/apiError";
import { mintDeviceToken } from "@/lib/deviceAgent/tokens";
import { deviceAgentGate, MAX_ACTIVE_DEVICES } from "@/lib/deviceAgent/access";
import { displayStatus } from "@/lib/deviceAgent/patchRule";

const ROUTE = "agent/devices";
const NOT_ENABLED = "Device reporting isn't enabled on this server yet (database migration 086 pending).";

const createSchema = z.object({
  name: z.string().trim().min(1, "name is required").max(80, "name must be 80 characters or fewer"),
});
const revokeSchema = z.object({ id: z.string().uuid("id must be a device id") });

type DeviceRow = {
  id: string;
  name: string;
  token_prefix: string;
  created_at: string;
  revoked_at: string | null;
  last_seen_at: string | null;
  hostname: string | null;
  os_family: string | null;
  os_name: string | null;
  os_version: string | null;
  agent_version: string | null;
  patch_status: string;
  evaluation: unknown;
  last_match: unknown;
  matched_at: string | null;
};

const LIST_COLUMNS =
  "id, name, token_prefix, created_at, revoked_at, last_seen_at, hostname, os_family, os_name, os_version, agent_version, patch_status, evaluation, last_match, matched_at";

/** The client shape: never token_hash, and the match cut to what the page shows. */
export function toClientDevice(row: DeviceRow, now: Date) {
  const match = row.last_match as { cves?: unknown[]; osEol?: unknown; coverage?: unknown; status?: string } | null;
  return {
    id: row.id,
    name: row.name,
    token_prefix: row.token_prefix,
    created_at: row.created_at,
    revoked_at: row.revoked_at,
    last_seen_at: row.last_seen_at,
    hostname: row.hostname,
    os: { family: row.os_family, name: row.os_name, version: row.os_version },
    agent_version: row.agent_version,
    status: row.revoked_at ? "revoked" : displayStatus(row.patch_status, row.last_seen_at, now),
    evaluation: row.evaluation ?? null,
    match: match
      ? {
          status: match.status ?? null,
          cves: Array.isArray(match.cves) ? match.cves.slice(0, 25) : [],
          cve_count: Array.isArray(match.cves) ? match.cves.length : 0,
          os_eol: match.osEol ?? null,
          coverage: match.coverage ?? null,
        }
      : null,
    matched_at: row.matched_at,
  };
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Devices can only be managed from a logged-in session, not with an API key." });
  }

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin
      .from("agent_devices")
      .select(LIST_COLUMNS)
      .eq("owner", caller.ownerId)
      .order("created_at", { ascending: false });
    if (error) {
      if (isMissingSchemaError(error)) return res.status(200).json({ devices: [], enabled: false });
      return respondInternalError(res, ROUTE, error);
    }
    const now = new Date();
    return res.status(200).json({ devices: ((data ?? []) as DeviceRow[]).map((r) => toClientDevice(r, now)), enabled: true });
  }

  if (req.method === "POST") {
    const parsed = parseBody(createSchema, req.body, res);
    if (!parsed) return;

    const gate = await deviceAgentGate(supabaseAdmin, caller.ownerId);
    if (gate === "error") return respondInternalError(res, ROUTE, { message: "plan lookup failed" });
    if (gate === "denied") return res.status(403).json({ error: "Device patch reporting needs a Pro plan or above." });

    const { count, error: countError } = await supabaseAdmin
      .from("agent_devices")
      .select("id", { count: "exact", head: true })
      .eq("owner", caller.ownerId)
      .is("revoked_at", null);
    if (countError) {
      if (isMissingSchemaError(countError)) return res.status(503).json({ error: NOT_ENABLED });
      return respondInternalError(res, ROUTE, countError);
    }
    if ((count ?? 0) >= MAX_ACTIVE_DEVICES) {
      return res.status(400).json({ error: `Device limit reached (${MAX_ACTIVE_DEVICES} active). Revoke a device you no longer use first.` });
    }

    const minted = mintDeviceToken();
    const { data, error } = await supabaseAdmin
      .from("agent_devices")
      .insert({ owner: caller.ownerId, name: parsed.name, token_hash: minted.token_hash, token_prefix: minted.token_prefix, created_by: caller.ownerId })
      .select("id, name, token_prefix, created_at")
      .single();
    if (error) {
      if (isMissingSchemaError(error)) return res.status(503).json({ error: NOT_ENABLED });
      return respondInternalError(res, ROUTE, error);
    }

    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "agent_device.created",
      resourceType: "agent_device",
      resourceId: data.id,
      metadata: { name: parsed.name, token_prefix: data.token_prefix },
    });

    // The only time the token is returned: it isn't stored, so it can't be shown again.
    return res.status(201).json({ ...data, token: minted.plaintext });
  }

  if (req.method === "DELETE") {
    const parsed = parseBody(revokeSchema, req.body, res);
    if (!parsed) return;
    // Revoke rather than delete, so the device's history stays visible.
    const { data, error } = await supabaseAdmin
      .from("agent_devices")
      .update({ revoked_at: new Date().toISOString() })
      .eq("id", parsed.id)
      .eq("owner", caller.ownerId)
      .is("revoked_at", null)
      .select("id")
      .maybeSingle();
    if (error) {
      if (isMissingSchemaError(error)) return res.status(503).json({ error: NOT_ENABLED });
      return respondInternalError(res, ROUTE, error);
    }
    if (!data) return res.status(404).json({ error: "Device not found" });

    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "agent_device.revoked",
      resourceType: "agent_device",
      resourceId: parsed.id,
    });
    return res.status(200).json({ ok: true });
  }

  res.setHeader("Allow", "GET, POST, DELETE");
  return res.status(405).json({ error: "Method not allowed" });
}

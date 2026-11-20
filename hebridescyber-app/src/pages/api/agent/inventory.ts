// POST /api/agent/inventory: the device agent (agent/ at the repo root)
// reports OS version, installed software and pending updates.
//
// Authenticated by a per-device token (deviceAgent/tokens.ts), never a
// session or API key. Everything in the body is untrusted: the token can be
// copied off the machine, so its holder controls the payload. Hence, in
// order:
//   1. a per-IP rate limit, before any work;
//   2. token format check, then a per-token rate limit keyed on the token's
//      hash, both before the database is touched;
//   3. token lookup (revoked or unknown: the same 401);
//   4. the owner's plan (deviceAgentGate);
//   5. a 2 MB body limit (Next's bodyParser answers 413) and field-by-field
//      schema validation; unknown keys are stripped, never stored.
//
// The 14-day rule is evaluated here from the pending updates, with the
// previous CVE / end-of-life match carried forward; the heavier matching runs
// in src/scripts/match-device-inventories.ts, never in this request.
import type { NextApiRequest, NextApiResponse } from "next";
import { supabaseAdmin } from "@/lib/supabaseAdmin";
import { checkRateLimit, getClientIp } from "@/lib/rateLimit";
import { respondInternalError } from "@/lib/apiError";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { bearerToken, hashDeviceToken, isWellFormedDeviceToken, resolveDeviceToken } from "@/lib/deviceAgent/tokens";
import { inventorySchema } from "@/lib/deviceAgent/inventorySchema";
import { evaluatePatchRule } from "@/lib/deviceAgent/patchRule";
import { asDeviceMatch, carryMatchForward } from "@/lib/deviceAgent/matching";
import { deviceAgentGate } from "@/lib/deviceAgent/access";

// A literal: Next reads route config statically. Matches LIMITS.bodyBytes.
export const config = { api: { bodyParser: { sizeLimit: "2mb" } } };

/** An office behind one NAT address can have many devices reporting daily. */
export const IP_POLICY = { max: 600, windowSeconds: 60 * 60 };
/** The agent reports once a day; retries and manual runs fit well inside this. */
export const TOKEN_POLICY = { max: 12, windowSeconds: 60 * 60 };
/** Reports kept per device; older ones are deleted on each upload. */
export const KEEP_INVENTORIES = 10;

const ROUTE = "agent/inventory";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }

  const ipLimit = await checkRateLimit(getClientIp(req), "agent-inventory-ip", IP_POLICY);
  if (!ipLimit.allowed) {
    res.setHeader("Retry-After", String(ipLimit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many requests from this address." });
  }

  const token = bearerToken(req.headers.authorization);
  if (!token || !isWellFormedDeviceToken(token)) {
    return res.status(401).json({ error: "Missing or invalid device token." });
  }

  const tokenLimit = await checkRateLimit(hashDeviceToken(token).slice(0, 32), "agent-inventory-token", TOKEN_POLICY);
  if (!tokenLimit.allowed) {
    res.setHeader("Retry-After", String(tokenLimit.retryAfterSeconds));
    return res.status(429).json({ error: "Too many reports from this device; try again later." });
  }

  if (!String(req.headers["content-type"] ?? "").toLowerCase().startsWith("application/json")) {
    return res.status(415).json({ error: "Send the inventory as application/json." });
  }

  const resolved = await resolveDeviceToken(supabaseAdmin, token);
  if (!resolved.ok) {
    if (resolved.reason === "error") {
      const err = resolved.error as { code?: string; message?: string } | undefined;
      if (isMissingSchemaError(err)) return res.status(503).json({ error: "Device reporting isn't enabled on this server yet." });
      return respondInternalError(res, ROUTE, err ?? null);
    }
    return res.status(401).json({ error: "Missing or invalid device token." });
  }
  const device = resolved.device;

  const gate = await deviceAgentGate(supabaseAdmin, device.owner);
  if (gate === "error") return respondInternalError(res, ROUTE, { message: "plan lookup failed" }, { status: 503 });
  if (gate === "denied") {
    return res.status(403).json({ error: "This account's plan doesn't include device patch reporting." });
  }

  const parsed = inventorySchema.safeParse(req.body);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    return res.status(400).json({ error: `${issue.path.join(".") || "body"}: ${issue.message}` });
  }
  const inventory = parsed.data;

  const now = new Date();
  const previousMatch = carryMatchForward(asDeviceMatch(device.last_match), inventory);
  const evaluation = evaluatePatchRule({ inventory, previousFirstSeen: device.pending_first_seen, match: previousMatch, now });
  const { pendingFirstSeen, ...storedEvaluation } = evaluation;

  const { error: insertError } = await supabaseAdmin.from("agent_inventories").insert({
    device_id: device.id,
    owner: device.owner,
    received_at: now.toISOString(),
    collected_at: inventory.collected_at,
    inventory,
  });
  if (insertError) return respondInternalError(res, ROUTE, insertError);

  const { error: updateError } = await supabaseAdmin
    .from("agent_devices")
    .update({
      last_seen_at: now.toISOString(),
      hostname: inventory.hostname || null,
      os_family: inventory.os.family,
      os_name: inventory.os.name || null,
      os_version: inventory.os.version || null,
      agent_version: inventory.agent_version || null,
      pending_first_seen: pendingFirstSeen,
      patch_status: evaluation.status,
      evaluation: storedEvaluation,
      last_match: previousMatch,
    })
    .eq("id", device.id)
    .is("revoked_at", null);
  if (updateError) return respondInternalError(res, ROUTE, updateError);

  await trimOldInventories(device.id);

  return res.status(200).json({ device_id: device.id, patch_status: evaluation.status, summary: evaluation.summary });
}

/** Best-effort: keeps the newest KEEP_INVENTORIES reports for the device. */
async function trimOldInventories(deviceId: string): Promise<void> {
  try {
    const { data } = await supabaseAdmin
      .from("agent_inventories")
      .select("id")
      .eq("device_id", deviceId)
      .order("received_at", { ascending: false })
      .range(KEEP_INVENTORIES, KEEP_INVENTORIES + 99);
    const ids = (data ?? []).map((r: { id: number }) => r.id);
    if (ids.length > 0) await supabaseAdmin.from("agent_inventories").delete().in("id", ids);
  } catch {
    // Housekeeping only: the next upload trims again.
  }
}

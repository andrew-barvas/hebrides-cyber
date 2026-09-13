// Webhook management — GET (list), POST (create), DELETE (remove).
//
// Deliberately session-only, mirroring src/pages/api/keys.ts: a webhook can't
// read account data the way an API key can, but a forged completion event
// sent to whatever URL an attacker chose is still not something an API key
// should be able to set up on its own.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { generateWebhookSecret } from "@/lib/webhooks";
import { logAuditEvent } from "@/lib/audit";
import { validateNoSsrf } from "@/lib/ownership";
import { parseBody } from "@/lib/validate";

const createSchema = z.object({
  url: z.string().url("url must be a valid URL"),
  name: z.string().max(60).optional(),
});

const deleteWebhookSchema = z.object({
  id: z.string().min(1, "id is required"),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  if (caller.via !== "session") {
    return res.status(403).json({ error: "Webhooks can only be managed from a logged-in session, not with an API key." });
  }

  if (req.method === "GET") {
    // Never select `secret` for the list view — it only needs to exist
    // server-side, to sign outgoing deliveries.
    const { data, error } = await supabaseAdmin
      .from("webhooks")
      .select("id, name, url, failure_count, last_success_at, last_failure_at, disabled_at, created_at")
      .eq("owner", caller.ownerId)
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ webhooks: data ?? [] });
  }

  if (req.method === "POST") {
    const body = parseBody(createSchema, req.body, res);
    if (!body) return;
    const { url, name } = body;

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return res.status(400).json({ error: "url must be a valid URL" });
    }
    if (parsed.protocol !== "https:") {
      return res.status(400).json({ error: "url must use https — a plaintext http endpoint can't keep the signing secret confidential in transit" });
    }

    // Unlike the Slack/Teams vendor fields (webhookUrlValidation.ts's
    // hostname allowlist — this URL is genuinely arbitrary, owner-controlled
    // infrastructure, so the check here is validateNoSsrf's private-IP/
    // metadata-endpoint block rather than a fixed allowlist. This is
    // defense in depth for immediate customer feedback — the actual
    // enforcement that matters is in src/lib/webhooks.ts's deliverOne(),
    // which re-checks on every delivery rather than trusting this one-time
    // save-time result (DNS can legitimately repoint after registration).
    try {
      await validateNoSsrf(url);
    } catch (err) {
      return res.status(400).json({ error: (err as Error).message });
    }

    const label = (name ?? "").trim().slice(0, 60) || null;

    const { data: existing } = await supabaseAdmin
      .from("webhooks")
      .select("id")
      .eq("owner", caller.ownerId);

    if ((existing?.length ?? 0) >= 20) {
      return res.status(400).json({ error: "Webhook limit reached (20). Remove an unused one first." });
    }

    const secret = generateWebhookSecret();
    const { data, error } = await supabaseAdmin
      .from("webhooks")
      .insert({ owner: caller.ownerId, url, name: label, secret })
      .select("id, name, url, created_at")
      .single();

    if (error) return res.status(500).json({ error: error.message });

    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "webhook.created",
      resourceType: "webhook",
      resourceId: data.id,
      metadata: { url, name: label },
    });

    // The only time the plaintext secret is ever returned. Unlike an API key,
    // it IS still readable server-side afterwards (see src/lib/webhooks.ts
    // for why), but the UI should still treat this as the one moment to
    // copy it down, rather than adding a "reveal" affordance later.
    return res.status(201).json({ ...data, secret });
  }

  if (req.method === "DELETE") {
    const body = parseBody(deleteWebhookSchema, req.body, res);
    if (!body) return;
    const { id } = body;

    const { error } = await supabaseAdmin
      .from("webhooks")
      .delete()
      .eq("id", id)
      .eq("owner", caller.ownerId);

    if (error) return res.status(500).json({ error: error.message });

    await logAuditEvent(supabaseAdmin, {
      actorId: caller.ownerId,
      action: "webhook.removed",
      resourceType: "webhook",
      resourceId: id,
    });

    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: "Method not allowed" });
}

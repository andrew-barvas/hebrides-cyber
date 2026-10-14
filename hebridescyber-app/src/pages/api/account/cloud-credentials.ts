// GET/POST/DELETE /api/account/cloud-credentials — manages stored cloud
// provider credentials for E-32 cloud posture scanning. Credentials are
// encrypted with AES-256-GCM before storage (src/lib/credentialEncryption.ts)
// and written to cloud_credentials.credentials_encrypted (see
// sql/migrations/030_cloud_credentials.sql). Agency-plan only for writes.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { planGate } from "@/lib/planAccess";
import { parseBody } from "@/lib/validate";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { encryptCredentials, isCredentialEncryptionConfigured } from "@/lib/credentialEncryption";

const awsSchema = z.object({
  provider: z.literal("aws"),
  label: z.string().min(1).max(100),
  credentials: z.object({
    accessKeyId: z.string().min(16).max(128),
    secretAccessKey: z.string().min(1),
    region: z.string().max(30).optional(),
  }),
});

const azureSchema = z.object({
  provider: z.literal("azure"),
  label: z.string().min(1).max(100),
  credentials: z.object({
    tenantId: z.string().uuid(),
    clientId: z.string().uuid(),
    clientSecret: z.string().min(1),
    subscriptionId: z.string().uuid(),
  }),
});

const gcpSchema = z.object({
  provider: z.literal("gcp"),
  label: z.string().min(1).max(100),
  credentials: z.object({
    projectId: z.string().min(1),
    serviceAccountKey: z.string().min(1),
  }),
});

const postBodySchema = z.discriminatedUnion("provider", [awsSchema, azureSchema, gcpSchema]);

const deleteBodySchema = z.object({
  id: z.string().uuid(),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST" && req.method !== "DELETE") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Cloud credentials can only be managed from a logged-in session." });
  }

  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin
      .from("cloud_credentials")
      .select("id, provider, label, validated_at, created_at")
      .eq("owner", caller.ownerId)
      .order("created_at", { ascending: false });

    // Migration 030 not applied to this database yet — degrade to "no
    // credentials" rather than 500ing the Dashboard for every Agency
    // account on every load.
    if (error && !isMissingSchemaError(error)) {
      return res.status(500).json({ error: error.message });
    }
    return res.status(200).json({ credentials: data ?? [] });
  }

  // Plan-gate writes (POST/DELETE) to Agency tier
  const gate = await planGate(supabaseAdmin, caller.ownerId, "agency");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan — try again." });
  if (gate === "denied") {
    return res.status(403).json({ error: "Cloud posture scanning is an Agency-plan feature." });
  }

  if (req.method === "DELETE") {
    const parsed = parseBody(deleteBodySchema, req.body, res);
    if (!parsed) return;

    const { data: existing } = await supabaseAdmin
      .from("cloud_credentials")
      .select("id, owner")
      .eq("id", parsed.id)
      .maybeSingle();

    if (!existing) return res.status(404).json({ error: "Credential not found" });
    if (existing.owner !== caller.ownerId) return res.status(403).json({ error: "Forbidden" });

    const { error } = await supabaseAdmin.from("cloud_credentials").delete().eq("id", parsed.id);
    if (error) {
      if (isMissingSchemaError(error)) {
        return res.status(503).json({ error: "Cloud credentials aren't available on this account yet — try again shortly." });
      }
      return res.status(500).json({ error: error.message });
    }
    return res.status(200).json({ ok: true });
  }

  // POST — create or update a credential
  const parsed = parseBody(postBodySchema, req.body, res);
  if (!parsed) return;

  // Fail closed: never store cloud credentials in plaintext (finding S-1). If
  // the encryption key isn't configured, refuse the write rather than fall back.
  if (!isCredentialEncryptionConfigured()) {
    return res.status(503).json({
      error:
        "Secure credential storage isn't configured on this deployment yet, so cloud credentials can't be saved. Set CREDENTIALS_ENC_KEY and try again.",
    });
  }

  const { error } = await supabaseAdmin.from("cloud_credentials").upsert(
    {
      owner: caller.ownerId,
      provider: parsed.provider,
      label: parsed.label,
      credentials_encrypted: encryptCredentials(parsed.credentials),
    },
    { onConflict: "owner,provider,label" }
  );

  if (error) {
    if (isMissingSchemaError(error)) {
      return res.status(503).json({ error: "Cloud credentials aren't available on this account yet — try again shortly." });
    }
    return res.status(500).json({ error: error.message });
  }
  return res.status(200).json({ ok: true });
}

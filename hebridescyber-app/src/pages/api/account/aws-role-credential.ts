// GET/POST /api/account/aws-role-credential — connects an AWS account for the
// Prowler IAM check by cross-account role instead of access keys.
//
// Two-step, because the customer needs our external id BEFORE they can write
// the role's trust policy:
//   1. POST { label }              → we generate and store an external id for
//                                    that account label and return it.
//   2. POST { label, roleArn }     → we store the role ARN the customer created
//                                    (same external id; re-posting never rotates it).
// The row lives in cloud_credentials (provider "aws", authMode "role"),
// encrypted with AES-256-GCM like every other cloud credential. Agency-plan only.
// The external id is a confused-deputy guard, not a secret, so GET returns it
// so the setup instructions can be shown again.
import type { NextApiRequest, NextApiResponse } from "next";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { planGate } from "@/lib/planAccess";
import { parseBody } from "@/lib/validate";
import { isMissingSchemaError } from "@/lib/dbErrors";
import { decryptCredentials, encryptCredentials, isCredentialEncryptionConfigured } from "@/lib/credentialEncryption";

const postBodySchema = z.object({
  label: z.string().min(1).max(100),
  roleArn: z
    .string()
    .regex(/^arn:aws:iam::\d{12}:role\/[\w+=,.@/-]{1,512}$/, "Must be an IAM role ARN, e.g. arn:aws:iam::123456789012:role/HebridesCyberAudit")
    .optional(),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });
  if (caller.via !== "session") {
    return res.status(403).json({ error: "Cloud credentials can only be managed from a logged-in session." });
  }

  const gate = await planGate(supabaseAdmin, caller.ownerId, "agency");
  if (gate === "error") return res.status(500).json({ error: "Could not check your plan — try again." });
  if (gate === "denied") return res.status(403).json({ error: "Cloud posture scanning is an Agency-plan feature." });

  if (!isCredentialEncryptionConfigured()) {
    return res.status(503).json({
      error:
        "Secure credential storage isn't configured on this deployment yet, so cloud credentials can't be saved. Set CREDENTIALS_ENC_KEY and try again.",
    });
  }

  const { data: rows, error: readError } = await supabaseAdmin
    .from("cloud_credentials")
    .select("id, label, credentials_encrypted")
    .eq("owner", caller.ownerId)
    .eq("provider", "aws");
  if (readError) {
    if (isMissingSchemaError(readError)) return res.status(200).json({ roles: [], platformAccountId: null });
    return res.status(500).json({ error: readError.message });
  }

  const roles: Array<{ id: string; label: string; externalId: string; roleArn: string | null }> = [];
  for (const row of rows ?? []) {
    try {
      const c = decryptCredentials(row.credentials_encrypted);
      if (c.authMode === "role") roles.push({ id: row.id, label: row.label, externalId: c.externalId, roleArn: c.roleArn || null });
    } catch {
      // Undecryptable (key rotated): not listed rather than failing the page.
    }
  }

  // The AWS account our scan identity lives in, for the customer's trust policy.
  const platformAccountId = process.env.PROWLER_PLATFORM_AWS_ACCOUNT_ID ?? null;
  if (req.method === "GET") return res.status(200).json({ roles, platformAccountId });

  const parsed = parseBody(postBodySchema, req.body, res);
  if (!parsed) return;

  const existing = roles.find((r) => r.label === parsed.label);
  const externalId = existing?.externalId ?? `hc-${randomBytes(16).toString("hex")}`;
  const roleArn = parsed.roleArn ?? existing?.roleArn ?? "";

  const { error } = await supabaseAdmin.from("cloud_credentials").upsert(
    {
      owner: caller.ownerId,
      provider: "aws",
      label: parsed.label,
      credentials_encrypted: encryptCredentials({ authMode: "role", externalId, roleArn }),
    },
    { onConflict: "owner,provider,label" }
  );
  if (error) {
    if (isMissingSchemaError(error)) {
      return res.status(503).json({ error: "Cloud credentials aren't available on this account yet — try again shortly." });
    }
    return res.status(500).json({ error: error.message });
  }
  return res.status(200).json({ label: parsed.label, externalId, roleArn: roleArn || null, platformAccountId });
}

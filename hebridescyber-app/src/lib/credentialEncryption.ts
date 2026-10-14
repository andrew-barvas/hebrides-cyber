// Application-layer envelope encryption for stored third-party secrets —
// specifically the cloud-provider credentials in `cloud_credentials`
// (AWS/Azure/GCP keys into a customer's own accounts). Migration 030 named the
// column `credentials_encrypted` and claimed "pgcrypto column-level
// encryption", but nothing ever encrypted it — the values were plaintext JSONB
// (review finding S-1). This provides the real thing: AES-256-GCM with a
// server-only key, authenticated so tampering is detected.
//
// Key: CREDENTIALS_ENC_KEY (server env only — never NEXT_PUBLIC_*). 32 bytes,
// supplied as base64 (recommended) or hex. Generate one with:
//   node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
//
// Fail-closed: if the key is unset, writes refuse (the API returns 503) rather
// than silently storing plaintext again. Legacy plaintext rows written before
// this remain readable (decrypt passes them through) until they are re-saved.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ALGO = "aes-256-gcm";

export type EncryptedBlob = { v: 1; iv: string; tag: string; data: string };

function getKey(): Buffer | null {
  const raw = process.env.CREDENTIALS_ENC_KEY;
  if (!raw) return null;
  const key = /^[0-9a-fA-F]{64}$/.test(raw) ? Buffer.from(raw, "hex") : Buffer.from(raw, "base64");
  return key.length === 32 ? key : null;
}

/** Whether a valid 32-byte CREDENTIALS_ENC_KEY is configured. */
export function isCredentialEncryptionConfigured(): boolean {
  return getKey() !== null;
}

/** True when `value` is a blob produced by {@link encryptCredentials}. */
export function isEncryptedBlob(value: unknown): value is EncryptedBlob {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return v.v === 1 && typeof v.iv === "string" && typeof v.tag === "string" && typeof v.data === "string";
}

/** Encrypts a credentials object. Throws if no key is configured. */
export function encryptCredentials(plain: Record<string, unknown>): EncryptedBlob {
  const key = getKey();
  if (!key) throw new Error("CREDENTIALS_ENC_KEY is not set or is not a 32-byte key");
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGO, key, iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(plain), "utf8"), cipher.final()]);
  return {
    v: 1,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: data.toString("base64"),
  };
}

/**
 * Decrypts a stored credentials value. A legacy plaintext object (pre-S-1-fix)
 * is returned unchanged so existing credentials keep working. An encrypted blob
 * requires the key — throws if it is missing or if the ciphertext fails its
 * authentication tag (tampering / wrong key).
 */
export function decryptCredentials(stored: unknown): Record<string, string> {
  if (!isEncryptedBlob(stored)) {
    return (stored ?? {}) as Record<string, string>;
  }
  const key = getKey();
  if (!key) throw new Error("CREDENTIALS_ENC_KEY is not set — cannot decrypt stored credentials");
  const decipher = createDecipheriv(ALGO, key, Buffer.from(stored.iv, "base64"));
  decipher.setAuthTag(Buffer.from(stored.tag, "base64"));
  const out = Buffer.concat([decipher.update(Buffer.from(stored.data, "base64")), decipher.final()]);
  return JSON.parse(out.toString("utf8")) as Record<string, string>;
}

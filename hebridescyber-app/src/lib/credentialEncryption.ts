// Application-layer envelope encryption for stored third-party secrets: the
// cloud-provider credentials in `cloud_credentials` (AWS/Azure/GCP keys into a
// customer's own accounts) and, in string form below, every other stored token,
// password and session cookie. Migration 030 named the column
// `credentials_encrypted` and claimed "pgcrypto column-level encryption", but
// nothing ever encrypted it — the values were plaintext JSONB
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

// ---- Single-string secrets (API tokens, passwords, session cookies) ---------
//
// The object API above fits cloud_credentials' JSONB column. Everything else
// that stores a live secret (ticket-tracker and on-call tokens, authenticated-
// scan cookies and Basic Auth passwords) keeps it in a plain `text` column, so
// the same AES-256-GCM envelope is stored as one string:
//   enc:v1:<iv>:<tag>:<data>   (each part base64, which never contains ':')
// A value without the prefix is a legacy plaintext secret written before this
// existed: it still decrypts (unchanged) until the row is re-saved or the
// one-off `npm run secrets:encrypt-existing` rewrites it.

const SECRET_PREFIX = "enc:v1:";

/** Shown to the customer when a write is refused because no key is configured. */
export const ENCRYPTION_NOT_CONFIGURED_MESSAGE =
  "Secure credential storage isn't configured on this deployment yet, so this credential can't be saved. Please try again shortly.";

/** True when `value` was produced by {@link encryptSecret}. */
export function isEncryptedSecret(value: unknown): value is string {
  return typeof value === "string" && value.startsWith(SECRET_PREFIX);
}

/** Encrypts one secret string. Throws if no key is configured. */
export function encryptSecret(plain: string): string {
  const blob = encryptCredentials({ s: plain });
  return `${SECRET_PREFIX}${blob.iv}:${blob.tag}:${blob.data}`;
}

/**
 * Decrypts a stored secret. Legacy plaintext is returned unchanged. Throws if
 * an encrypted value can't be decrypted (key missing or rotated, or the
 * ciphertext was tampered with).
 */
export function decryptSecret(stored: string): string {
  if (!isEncryptedSecret(stored)) return stored;
  const [iv, tag, data] = stored.slice(SECRET_PREFIX.length).split(":");
  if (!iv || !tag || !data) throw new Error("Malformed encrypted secret");
  return decryptCredentials({ v: 1, iv, tag, data }).s;
}

/**
 * A copy of `row` with the named string fields encrypted (null/empty fields are
 * left alone). Throws if no key is configured — callers check
 * {@link isCredentialEncryptionConfigured} first and answer 503.
 */
export function sealSecrets<T extends Record<string, unknown>>(row: T, fields: readonly (keyof T & string)[]): T {
  const out: Record<string, unknown> = { ...row };
  for (const f of fields) {
    const v = out[f];
    if (typeof v === "string" && v !== "") out[f] = encryptSecret(v);
  }
  return out as T;
}

/**
 * A copy of `row` with the named fields decrypted, or null if any of them can't
 * be (key missing or rotated, tampered value). Callers treat null as "this
 * credential is unusable right now" and skip it — never as plaintext.
 */
export function revealSecrets<T extends Record<string, unknown>>(row: T, fields: readonly (keyof T & string)[]): T | null {
  const out: Record<string, unknown> = { ...row };
  try {
    for (const f of fields) {
      const v = out[f];
      if (typeof v === "string" && v !== "") out[f] = decryptSecret(v);
    }
  } catch {
    return null;
  }
  return out as T;
}

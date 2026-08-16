// Token generation for shareable report links.
import { randomBytes } from "node:crypto";

/**
 * Unlike an API key or webhook secret, this token goes directly into a URL
 * path — no "hc_live_"-style prefix, since there's nothing here that needs to
 * be recognisable as a credential type when logged (URLs end up in access
 * logs, referrer headers, browser history; a share token is meant to be less
 * sensitive than an API key by design — it only grants read access to one
 * report, never write access or account data).
 */
export function generateShareToken(): string {
  return randomBytes(24).toString("base64url");
}

export function isExpired(expiresAt: string | null): boolean {
  return expiresAt !== null && new Date(expiresAt) < new Date();
}

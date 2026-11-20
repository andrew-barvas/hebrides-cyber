// Per-device tokens for the patch-audit agent (agent/ at the repo root).
//
// Stored only as a SHA-256 hash, like API keys (apiKeys.ts explains why a
// fast hash is right for high-entropy random tokens). The plaintext is shown
// once, when the device is added, and pasted into `hebrides-agent enrol`.
//
// A distinct prefix ("hcd_", not "hc_live_") keeps the two credential types
// apart: a device token can only post an inventory, and an API key is never
// accepted by the agent endpoint.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";

export const DEVICE_TOKEN_PREFIX = "hcd_";
/** Must match TokenPattern in agent/internal/upload/upload.go. */
export const DEVICE_TOKEN_RE = /^hcd_[A-Za-z0-9_-]{43}$/;
const PREFIX_DISPLAY_LENGTH = 12;

export type MintedDeviceToken = {
  /** Full token: return to the caller once, never persist. */
  plaintext: string;
  token_hash: string;
  token_prefix: string;
};

export function hashDeviceToken(plaintext: string): string {
  return createHash("sha256").update(plaintext).digest("hex");
}

export function mintDeviceToken(): MintedDeviceToken {
  // 32 random bytes in base64url is exactly 43 characters.
  const plaintext = `${DEVICE_TOKEN_PREFIX}${randomBytes(32).toString("base64url")}`;
  return { plaintext, token_hash: hashDeviceToken(plaintext), token_prefix: plaintext.slice(0, PREFIX_DISPLAY_LENGTH) };
}

export function isWellFormedDeviceToken(token: string): boolean {
  return DEVICE_TOKEN_RE.test(token);
}

/** The bearer token from an Authorization header, or null. */
export function bearerToken(header: string | string[] | undefined): string | null {
  const value = Array.isArray(header) ? header[0] : header;
  if (!value?.startsWith("Bearer ")) return null;
  const token = value.slice(7).trim();
  return token || null;
}

export type AgentDevice = {
  id: string;
  owner: string;
  name: string;
  pending_first_seen: Record<string, string>;
  last_match: unknown;
  matched_at: string | null;
};

export type ResolveResult = { ok: true; device: AgentDevice } | { ok: false; reason: "unknown" | "revoked" | "error"; error?: unknown };

/**
 * The device a token belongs to. Revoked and unknown tokens are told apart
 * for logging only; the route answers both with the same 401.
 */
export async function resolveDeviceToken(supabaseAdmin: SupabaseClient, plaintext: string): Promise<ResolveResult> {
  const hash = hashDeviceToken(plaintext);
  const { data, error } = await supabaseAdmin
    .from("agent_devices")
    .select("id, owner, name, token_hash, revoked_at, pending_first_seen, last_match, matched_at")
    .eq("token_hash", hash)
    .maybeSingle();
  if (error) return { ok: false, reason: "error", error };
  if (!data) return { ok: false, reason: "unknown" };
  // Belt and braces after the indexed equality lookup, as apiKeys.ts does.
  const a = Buffer.from(hash);
  const b = Buffer.from(String(data.token_hash));
  if (a.length !== b.length || !timingSafeEqual(a, b)) return { ok: false, reason: "unknown" };
  if (data.revoked_at) return { ok: false, reason: "revoked" };
  const seen = data.pending_first_seen;
  return {
    ok: true,
    device: {
      id: data.id,
      owner: data.owner,
      name: data.name,
      pending_first_seen: seen && typeof seen === "object" && !Array.isArray(seen) ? (seen as Record<string, string>) : {},
      last_match: data.last_match ?? null,
      matched_at: data.matched_at ?? null,
    },
  };
}

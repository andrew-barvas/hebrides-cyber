// API key generation and verification for the public REST API (/api/v1/*).
//
// Keys are stored only as a SHA-256 hash. The plaintext is shown to the user
// once, at creation, and is unrecoverable afterwards — a leaked database dump
// therefore can't be replayed against the API.
//
// SHA-256 (not bcrypt/argon2) is the right choice here specifically because
// these are high-entropy random tokens, not user-chosen passwords: there is no
// dictionary to attack, so a slow KDF would only add latency to every request.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import { scopesFromRow, type ApiScope } from "./apiScopes";

const LIVE_PREFIX = "hc_live_";
const PREFIX_DISPLAY_LENGTH = 16;

export type MintedKey = {
  /** Full key — return to the caller once, never persist. */
  plaintext: string;
  key_hash: string;
  key_prefix: string;
};

export function hashApiKey(plaintext: string): string {
  return createHash("sha256").update(plaintext).digest("hex");
}

export function mintApiKey(): MintedKey {
  // 32 bytes base64url ≈ 43 chars of ~192 bits entropy — far beyond guessing.
  const plaintext = `${LIVE_PREFIX}${randomBytes(32).toString("base64url")}`;
  return {
    plaintext,
    key_hash: hashApiKey(plaintext),
    key_prefix: plaintext.slice(0, PREFIX_DISPLAY_LENGTH),
  };
}

export function looksLikeApiKey(token: string): boolean {
  return token.startsWith(LIVE_PREFIX);
}

export type ApiKeyOwner = {
  ownerId: string;
  keyId: string;
  /** Empty = any address. See src/lib/ipAllowlist.ts. */
  allowedCidrs: string[];
  /** What the key may do. A row from before migration 062 has none stored and keeps every scope. */
  scopes: ApiScope[];
};

/**
 * Resolves an API key to its owner, or null if the key is unknown or revoked.
 * The IP allowlist is returned, not checked — that needs the request, so
 * apiAuth.ts enforces it.
 *
 * Takes the Supabase client as an argument rather than constructing one so
 * this stays unit-testable and callers control which credentials are used —
 * it must be a service-role client, since api_keys has no select policy that
 * would let an unauthenticated request read it.
 */
export async function resolveApiKey(
  supabaseAdmin: SupabaseClient,
  plaintext: string
): Promise<ApiKeyOwner | null> {
  const hash = hashApiKey(plaintext);

  // "*" rather than a column list: allowed_cidrs arrives with migration 042,
  // and naming it before that's applied would fail every key lookup — taking
  // the whole API down. Absent, it reads as "no allowlist", which is exactly
  // what an unmigrated database means.
  const { data } = await supabaseAdmin
    .from("api_keys")
    .select("*")
    .eq("key_hash", hash)
    .maybeSingle();

  if (!data || data.revoked_at) return null;

  // The lookup above already matched on an indexed equality, so this is belt
  // and braces rather than the primary defence — but comparing the returned
  // hash in constant time keeps the verification step itself free of a timing
  // signal regardless of how the row was fetched.
  const a = Buffer.from(hash);
  const b = Buffer.from(data.key_hash);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;

  // Telemetry, not correctness — started but not awaited, so it never adds
  // latency or turns into an error. It must be .then()'d: a PostgREST builder
  // only sends its request from then(), so the `void builder` this used to be
  // never ran, and every key showed "never used".
  supabaseAdmin
    .from("api_keys")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", data.id)
    .then(undefined, () => {});

  return {
    ownerId: data.owner,
    keyId: data.id,
    allowedCidrs: Array.isArray(data.allowed_cidrs) ? (data.allowed_cidrs as string[]) : [],
    scopes: scopesFromRow(data.scopes),
  };
}

/** Best-effort record of a request the key's IP allowlist refused, so the
 *  dashboard can show why a CI job started getting 401s. Awaited by the
 *  caller (the request is being refused, so latency doesn't matter) but
 *  never throws. */
export async function recordBlockedApiKeyUse(supabaseAdmin: SupabaseClient, keyId: string, ip: string): Promise<void> {
  try {
    await supabaseAdmin
      .from("api_keys")
      .update({ last_blocked_ip: ip.slice(0, 64), last_blocked_at: new Date().toISOString() })
      .eq("id", keyId);
  } catch {
    // Telemetry only.
  }
}

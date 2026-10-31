// RFC 6238 time-based one-time passwords (HMAC-SHA-1, 6 digits, 30 s step) —
// the only variant authenticator apps are guaranteed to accept, and the one
// the recorded-login MFA step (scanners/loginRecorder.ts) types into a target's
// MFA field. Dependency-free: node:crypto's HMAC plus a small RFC 4648 base32
// decoder. The shared secret and the generated code are credentials — callers
// never log or return either.
import { createHmac } from "node:crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP_SECONDS = 30;
const DIGITS = 6;
// 80 bits is the RFC 4226 minimum; 1024 bits is far beyond any real secret.
const MIN_SECRET_BYTES = 10;
const MAX_SECRET_BYTES = 128;

/** Strips the spaces/dashes authenticator apps display and upper-cases. */
export function normaliseTotpSecret(raw: string): string {
  return raw.replace(/[\s-]/g, "").replace(/=+$/, "").toUpperCase();
}

/** Decodes RFC 4648 base32, or returns null if it isn't valid. */
export function base32Decode(input: string): Buffer | null {
  const clean = normaliseTotpSecret(input);
  if (clean === "") return null;
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

/** True when `raw` is a base32 secret of a plausible length. */
export function isValidTotpSecret(raw: string): boolean {
  const key = base32Decode(raw);
  return key !== null && key.length >= MIN_SECRET_BYTES && key.length <= MAX_SECRET_BYTES;
}

/**
 * The current code for a base32 secret. Throws on an invalid secret — callers
 * validate with {@link isValidTotpSecret} first, so a bad secret is an error
 * result upstream, never a made-up code.
 */
export function generateTotp(secret: string, atMs: number = Date.now()): string {
  const key = base32Decode(secret);
  if (!key || key.length < MIN_SECRET_BYTES || key.length > MAX_SECRET_BYTES) throw new Error("Invalid TOTP secret");
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(atMs / 1000 / STEP_SECONDS)));
  const mac = createHmac("sha1", key).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(bin % 10 ** DIGITS).padStart(DIGITS, "0");
}

/** Milliseconds until the current code rolls over. */
export function msUntilNextTotp(atMs: number = Date.now()): number {
  return STEP_SECONDS * 1000 - (atMs % (STEP_SECONDS * 1000));
}

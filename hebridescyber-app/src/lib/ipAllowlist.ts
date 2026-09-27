// Per-API-key IP allowlists — a key with a non-empty allowlist only
// authenticates from those addresses (enforced in apiAuth.ts). An empty list
// means "any address", which is every key created before this existed.
//
// Built on node:net's BlockList rather than hand-rolled bit maths so IPv6
// works: a CI runner or office network reaching the API over IPv6 is common,
// and an IPv4-only matcher would lock those callers out with no clue why.
// Server-only (node:net) — the account UI leaves validation to the API.
import { BlockList, isIP } from "node:net";

export const MAX_ALLOWLIST_ENTRIES = 20;

type Family = "ipv4" | "ipv6";

export type ParsedCidr = { address: string; prefix: number; family: Family };

/**
 * Reduces an address as a proxy might report it to a bare IP: drops a
 * ":port" suffix (Azure puts one in X-Forwarded-For), IPv6 brackets and zone
 * IDs, and unwraps IPv4-mapped IPv6 ("::ffff:203.0.113.7") so it matches an
 * IPv4 entry. Returns null for anything that isn't an IP address.
 */
export function normaliseIp(raw: string): string | null {
  let value = raw.trim();
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(value);
  if (bracketed) value = bracketed[1];
  else if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(value)) value = value.slice(0, value.lastIndexOf(":"));
  value = value.replace(/%.*$/, "").toLowerCase();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(value);
  if (mapped) value = mapped[1];
  return isIP(value) ? value : null;
}

/** "203.0.113.7", "203.0.113.0/24", "2001:db8::/32". A bare address is a
 *  single host (/32 or /128). */
export function parseCidr(cidr: string): ParsedCidr | null {
  const [addressPart, prefixPart, extra] = cidr.trim().split("/");
  if (extra !== undefined || !addressPart) return null;
  const version = isIP(addressPart);
  if (version === 0) return null;
  const family: Family = version === 4 ? "ipv4" : "ipv6";
  const max = version === 4 ? 32 : 128;
  if (prefixPart === undefined) return { address: addressPart.toLowerCase(), prefix: max, family };
  if (!/^\d{1,3}$/.test(prefixPart)) return null;
  const prefix = Number(prefixPart);
  if (prefix > max) return null;
  return { address: addressPart.toLowerCase(), prefix, family };
}

export type AllowlistValidation = { ok: true; cidrs: string[] } | { ok: false; error: string };

/** Validates and tidies a list for storage: trimmed, lowercased, de-duplicated. */
export function validateAllowlist(entries: string[]): AllowlistValidation {
  const cidrs: string[] = [];
  for (const entry of entries) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const parsed = parseCidr(trimmed);
    if (!parsed) return { ok: false, error: `"${trimmed}" isn't an IP address or CIDR range (e.g. 203.0.113.7 or 203.0.113.0/24).` };
    if (parsed.prefix === 0) {
      return { ok: false, error: `"${trimmed}" allows every address. Remove the allowlist instead to allow any IP.` };
    }
    const tidy = parsed.prefix === (parsed.family === "ipv4" ? 32 : 128) ? parsed.address : `${parsed.address}/${parsed.prefix}`;
    if (!cidrs.includes(tidy)) cidrs.push(tidy);
  }
  if (cidrs.length > MAX_ALLOWLIST_ENTRIES) {
    return { ok: false, error: `An allowlist can hold at most ${MAX_ALLOWLIST_ENTRIES} entries.` };
  }
  return { ok: true, cidrs };
}

/**
 * True if `ip` falls inside any entry. An empty allowlist allows everything;
 * otherwise anything unparseable — the address or a stored entry — fails
 * closed, since this gates authentication.
 */
export function isIpAllowed(ip: string, cidrs: string[]): boolean {
  if (cidrs.length === 0) return true;
  const address = normaliseIp(ip);
  if (!address) return false;
  const list = new BlockList();
  for (const cidr of cidrs) {
    const parsed = parseCidr(cidr);
    if (parsed) list.addSubnet(parsed.address, parsed.prefix, parsed.family);
  }
  return list.check(address, isIP(address) === 4 ? "ipv4" : "ipv6");
}

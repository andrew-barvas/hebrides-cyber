// IP allowlisting — restricts API access to a set of approved IP addresses
// or CIDR ranges per organization. Pure validation functions; the actual
// middleware check is done in the API route handler.

export type AllowlistEntry = {
  cidr: string;
  label?: string;
};

function ipToNumber(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    result = (result << 8) | n;
  }
  return result >>> 0;
}

export function parseCidr(cidr: string): { network: number; mask: number } | null {
  const trimmed = cidr.trim();
  const slashIdx = trimmed.indexOf("/");

  if (slashIdx === -1) {
    const ip = ipToNumber(trimmed);
    if (ip === null) return null;
    return { network: ip, mask: 0xffffffff };
  }

  const ip = ipToNumber(trimmed.slice(0, slashIdx));
  const prefix = Number(trimmed.slice(slashIdx + 1));
  if (ip === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;

  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: (ip & mask) >>> 0, mask };
}

export function isIpInCidr(ip: string, cidr: string): boolean {
  const parsed = parseCidr(cidr);
  if (!parsed) return false;
  const ipNum = ipToNumber(ip);
  if (ipNum === null) return false;
  return ((ipNum & parsed.mask) >>> 0) === parsed.network;
}

export function isIpAllowed(ip: string, allowlist: AllowlistEntry[]): boolean {
  if (allowlist.length === 0) return true;
  return allowlist.some((entry) => isIpInCidr(ip, entry.cidr));
}

export function validateAllowlistEntry(cidr: string): { valid: true } | { valid: false; error: string } {
  const trimmed = cidr.trim();
  if (!trimmed) return { valid: false, error: "Empty CIDR" };
  const parsed = parseCidr(trimmed);
  if (!parsed) return { valid: false, error: `Invalid CIDR notation: ${trimmed}` };
  return { valid: true };
}

export function validateAllowlist(entries: AllowlistEntry[]): { valid: true } | { valid: false; errors: string[] } {
  const errors: string[] = [];
  for (const entry of entries) {
    const result = validateAllowlistEntry(entry.cidr);
    if (!result.valid) errors.push(result.error);
  }
  return errors.length === 0 ? { valid: true } : { valid: false, errors };
}

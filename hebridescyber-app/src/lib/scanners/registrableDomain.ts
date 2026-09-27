// The registrable domain ("eTLD+1") of a hostname: shop.example.co.uk →
// example.co.uk. Used where a check must reason about the domain a customer
// actually registered (RDAP expiry) or scope a list of hostnames to it
// (subdomain takeover).
//
// A curated list of multi-label public suffixes rather than the full Public
// Suffix List: this product's customers are overwhelmingly on .uk and the
// big gTLDs, and a wrong answer is harmless by construction — RDAP simply
// has no record for it, and the check reports nothing. Add suffixes here
// when a real customer domain needs one.
const MULTI_LABEL_SUFFIXES = new Set([
  // UK (Nominet second-level domains)
  "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk", "nhs.uk", "police.uk", "mod.uk",
  // Common elsewhere
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "org.nz", "net.nz",
  "co.za", "org.za",
  "co.jp", "ne.jp", "or.jp",
  "com.br", "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.cn", "co.in", "co.il", "co.kr",
]);

export function registrableDomain(hostname: string): string | null {
  const host = hostname.trim().toLowerCase().replace(/\.$/, "");
  const labels = host.split(".");
  if (labels.length < 2 || labels.some((l) => l === "") || /^[\d.]+$/.test(host) || host.includes(":")) return null;
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) return labels.length >= 3 ? labels.slice(-3).join(".") : null;
  return lastTwo;
}

/** Is `host` the registrable domain itself or a subdomain of it? */
export function isWithinDomain(host: string, domain: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  return h === domain || h.endsWith(`.${domain}`);
}

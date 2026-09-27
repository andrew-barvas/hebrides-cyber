// Domain registration health via RDAP (the registries' structured successor
// to WHOIS): when the site's registered domain expires, and — for generic
// TLDs — whether it carries a registrar transfer lock.
//
// An expired domain takes the website AND the business's email down at once,
// and a lapsed domain can be bought by someone else; it's one of the most
// common self-inflicted outages for small businesses, and certificate-expiry
// monitoring (tls.ts) doesn't cover it. Beagle Security includes domain
// expiry tracking even on its free tier.
//
// Evidence: the registry's own RDAP record, located through IANA's RDAP
// bootstrap file. No registry record (unsupported TLD, wrong registrable-
// domain guess) → not_applicable, never a finding.
import { registrableDomain } from "./registrableDomain";

export const RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
const BOOTSTRAP_TIMEOUT_MS = 8_000;
const RDAP_TIMEOUT_MS = 8_000;
const BOOTSTRAP_CACHE_MS = 24 * 60 * 60 * 1000;

export type DomainRegistrationResult =
  | {
      status: "checked";
      domain: string;
      expiresAt: string | null;
      daysUntilExpiry: number | null;
      registrar: string | null;
      statuses: string[];
      /** true if any transfer-prohibited status is set; false only on a generic
       *  TLD without one; null otherwise (a ccTLD without one proves nothing). */
      transferLocked: boolean | null;
    }
  | { status: "not_applicable"; note: string }
  | { status: "error"; note: string };

type Bootstrap = Map<string, string>;
let bootstrapCache: { at: number; map: Bootstrap } | null = null;

export function parseBootstrap(body: unknown): Bootstrap {
  const map: Bootstrap = new Map();
  const services = (body as { services?: unknown } | null)?.services;
  if (!Array.isArray(services)) return map;
  for (const service of services) {
    if (!Array.isArray(service) || !Array.isArray(service[0]) || !Array.isArray(service[1])) continue;
    const base = (service[1] as unknown[]).find((u): u is string => typeof u === "string" && u.startsWith("https://"));
    if (!base) continue;
    for (const tld of service[0] as unknown[]) if (typeof tld === "string") map.set(tld.toLowerCase(), base.endsWith("/") ? base : `${base}/`);
  }
  return map;
}

// Registry-supplied JSON: shapes are checked, not trusted.
type RdapDomain = {
  events?: Array<{ eventAction?: string; eventDate?: string }>;
  status?: unknown[];
  entities?: Array<{ roles?: string[]; vcardArray?: unknown }>;
};

/** The registrar's display name from its jCard ("fn" property). */
function registrarName(body: RdapDomain): string | null {
  const registrar = body.entities?.find((e) => Array.isArray(e?.roles) && e.roles.includes("registrar"));
  const properties = Array.isArray(registrar?.vcardArray) ? registrar.vcardArray[1] : null;
  if (!Array.isArray(properties)) return null;
  const fn = properties.find((p): p is unknown[] => Array.isArray(p) && p[0] === "fn");
  return typeof fn?.[3] === "string" ? fn[3] : null;
}

/** Pure: RDAP domain object → result fields. */
export function parseRdapDomain(domain: string, body: RdapDomain, now: Date): Extract<DomainRegistrationResult, { status: "checked" }> {
  const expiration = body.events?.find((e) => e.eventAction === "expiration")?.eventDate;
  const expiresMs = expiration ? Date.parse(expiration) : NaN;
  const statuses = (body.status ?? []).filter((s): s is string => typeof s === "string");
  const tld = domain.split(".").pop() ?? "";
  // A lock that's present is present on any TLD. Its *absence* only means
  // something on generic TLDs: many country-code registries don't use EPP
  // transfer statuses consistently, so there it proves nothing.
  const isGeneric = tld.length > 2;
  const hasLock = statuses.some((s) => /transfer prohibited/i.test(s));
  return {
    status: "checked",
    domain,
    expiresAt: Number.isNaN(expiresMs) ? null : new Date(expiresMs).toISOString(),
    daysUntilExpiry: Number.isNaN(expiresMs) ? null : Math.floor((expiresMs - now.getTime()) / 86_400_000),
    registrar: registrarName(body),
    statuses,
    transferLocked: hasLock ? true : isGeneric && statuses.length > 0 ? false : null,
  };
}

async function loadBootstrap(now: number): Promise<Bootstrap | null> {
  if (bootstrapCache && now - bootstrapCache.at < BOOTSTRAP_CACHE_MS) return bootstrapCache.map;
  try {
    const res = await fetch(RDAP_BOOTSTRAP_URL, { signal: AbortSignal.timeout(BOOTSTRAP_TIMEOUT_MS) });
    if (!res.ok) return null;
    const map = parseBootstrap(await res.json());
    if (map.size === 0) return null;
    bootstrapCache = { at: now, map };
    return map;
  } catch {
    return null;
  }
}

export async function checkDomainRegistration(targetUrl: string, now: Date = new Date()): Promise<DomainRegistrationResult> {
  let host: string;
  try {
    host = new URL(targetUrl).hostname;
  } catch {
    return { status: "error", note: "Invalid target URL" };
  }
  const domain = registrableDomain(host);
  if (!domain) return { status: "not_applicable", note: "No registered domain (e.g. a bare IP address)." };

  const bootstrap = await loadBootstrap(now.getTime());
  if (!bootstrap) return { status: "error", note: "IANA RDAP bootstrap unavailable" };
  const base = bootstrap.get(domain.split(".").pop()!);
  if (!base) return { status: "not_applicable", note: `The .${domain.split(".").pop()} registry doesn't publish RDAP.` };

  try {
    const res = await fetch(`${base}domain/${encodeURIComponent(domain)}`, {
      headers: { Accept: "application/rdap+json" },
      signal: AbortSignal.timeout(RDAP_TIMEOUT_MS),
    });
    if (res.status === 404) return { status: "not_applicable", note: `${domain} not found in the registry's RDAP service.` };
    if (!res.ok) return { status: "error", note: `RDAP lookup returned HTTP ${res.status}` };
    return parseRdapDomain(domain, (await res.json()) as RdapDomain, now);
  } catch (err) {
    return { status: "error", note: `RDAP lookup failed: ${(err as Error).message}` };
  }
}

/** Test hook: forget the cached bootstrap file. */
export function resetRdapBootstrapCache(): void {
  bootstrapCache = null;
}

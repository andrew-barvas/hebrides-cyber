// Which domain a hostname belongs to, from the full Public Suffix List
// (tldts). Two answers, because a site on a hosting platform's shared domain
// has two:
//
//   registrableDomain: the domain registered at a registry, from the PSL's
//     ICANN section: shop.example.co.uk → example.co.uk, mysite.github.io →
//     github.io. Use it for what lives at registry level: RDAP expiry, the
//     domain's email authentication (SPF/DMARC/DKIM), breach lookups by
//     email domain.
//   ownerDomain: the narrowest domain one customer controls, private
//     suffixes included: mysite.github.io → mysite.github.io,
//     app.azurewebsites.net → app.azurewebsites.net. Use it to scope
//     hostnames to the customer (subdomain enumeration, takeover candidates,
//     first-party scripts). With registrableDomain, a GitHub Pages site would
//     be treated as owning every other github.io site.
//
// This used to be a hand-picked suffix list, on the theory that a wrong
// answer was harmless. It wasn't: it mapped a school at
// www.stmarys.herts.sch.uk to herts.sch.uk (the whole county's zone, so the
// report graded the council's SPF/DMARC and listed other schools'
// subdomains), and unlisted ccSLDs such as co.ke to the registry's own zone.
// Both return null for IP addresses, localhost and bare public suffixes.
import { getDomain } from "tldts";

export function registrableDomain(hostname: string): string | null {
  return getDomain(hostname.trim());
}

export function ownerDomain(hostname: string): string | null {
  return getDomain(hostname.trim(), { allowPrivateDomains: true });
}

/** Is `host` the domain itself or a subdomain of it? */
export function isWithinDomain(host: string, domain: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  return h === domain || h.endsWith(`.${domain}`);
}

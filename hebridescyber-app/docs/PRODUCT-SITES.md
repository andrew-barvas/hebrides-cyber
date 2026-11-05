# Product sites: lookout.hebridescyber.co.uk and exploit.hebridescyber.co.uk

**Status (2026-11-01):** both pages are built in the main app. Lookout is live
at `/lookout` and linked from the services page, the footer and the sitemap.
Exploit is built at `/exploit` but **not launched**: it is noindex, unlinked and
carries a "Not yet available" banner until OT-13 (insurance and engagement
contract) is signed off. The subdomains answer only once the owner has done the
DNS and Azure steps below.

Product design lives elsewhere: [`DEFENSIVE-ASSESSMENT-PLAN.md`](DEFENSIVE-ASSESSMENT-PLAN.md)
(Lookout, P-06) and [`EXPLOIT-PRODUCT-PLAN.md`](EXPLOIT-PRODUCT-PLAN.md)
(Exploit, P-07). Lookout's copy source is `marketing/17-lookout-managed-exposure-review.md`.

## How the subdomains work

One Next.js app, not three sites, so sign-in, the theme and links into the
platform are shared.

- `src/lib/productSites.ts` maps each host to its page. On a product host, `/`
  is rewritten to the page, the page's own path redirects to `/`, and every
  other path (login, pricing, dashboard) redirects to `www`, where the session
  cookie lives.
- `src/proxy.ts` applies that before anything else; the rewritten page still
  gets the CSP nonce. Exploit gets `X-Robots-Tag: noindex, nofollow` on both
  its host and its path, as well as `robots` metadata.
- Product pages link into the platform with absolute `www` URLs
  (`mainSiteUrl`), so every link works from either host. A test checks this.
- Local testing: `lookout.localhost:3000` and `exploit.localhost:3000` map to
  the same pages.
- Lookout's canonical URL is `www.hebridescyber.co.uk/lookout`, which works
  before and after the DNS change. Switch it to the subdomain once that
  answers, if the owner wants the subdomain to be the indexed address.

### Owner steps (not done)

1. DNS at GoDaddy: a CNAME for `lookout` (and, at Exploit launch, `exploit`)
   pointing at the Static Web App's default hostname.
2. Azure Static Web Apps → Custom domains: add each subdomain and let Azure
   validate it and issue the certificate.
3. Check: `curl -I https://lookout.hebridescyber.co.uk/` returns 200, and
   `/login` on it returns 308 to `www`.

These should become OT items in `OWNER-TODO.md`.

## Competitor review (2026-11-01)

Homepages read: Detectify and Intruder (continuous exposure / attack-surface
management, the nearest to Lookout), and Pentera, Cobalt, NetSPI and Bishop Fox
(penetration testing and validation, the nearest to Exploit). What follows
records page **patterns**, not their wording, and was read from homepages only:
it says nothing about their product pages, pricing pages or contracts.

### What they all do

- **Hero:** an outcome headline ("find what's exploitable", "always-on
  exposure management"), one line on who it's for, and two calls to action
  (trial or demo).
- **Proof straight after the hero:** a customer logo wall, review-site ratings,
  customer counts, and outcome statistics.
- **Segmentation:** products split by layer (attack surface, application, API,
  cloud) or by buyer intent (continuous, point-in-time, adversary simulation),
  each with its own page.
- **Contrast framing:** against "legacy" scanners, "theoretical" alerts or
  once-a-year tests.
- **Objection-handling FAQ** near the end, and the same calls to action
  repeated top, middle and bottom.
- **Product shown sparingly:** a few screenshots or a video at most; the
  validation vendors mostly describe rather than show.

### Where they are weak, and Hebrides Cyber can be different

- **No prices on the homepage.** Every one of the six routes the visitor to a
  demo or contact form. Lookout publishes its prices on the page.
- **Authorisation and rules of engagement are not explained** on any of the
  six homepages, even by the vendors whose product sends attack traffic.
  Lookout has a "What Lookout sends to your systems" section; Exploit puts its
  authorisation steps at the centre of the page.
- **Enterprise proof we cannot match honestly:** logo walls, ratings,
  certifications and outcome statistics. We have none of these yet, so the
  pages use what is real instead: a sample report, the published check list,
  the trust page, a named engineer and published prices. Do not add invented
  statistics or logos.

### Deliberately not copied

- Naming tools or offensive capabilities in copy (brand rule and OT-14).
- Identity/Active Directory attack paths, password cracking, cloud privilege
  escalation and "exploit chaining" as features: `EXPLOIT-PRODUCT-PLAN.md`
  rules these out of the product, and none is built.
- Named-competitor comparison tables. Comparisons on the pages are between our
  own products and a generic penetration test, where every cell can be
  checked.

## Before Exploit launches

- OT-13 signed off, and the go decision from `EXPLOIT-PRODUCT-PLAN.md`.
- The engagement/scope record and the gate-side scope check are built: the page
  says the platform refuses anything outside the signed scope.
- Remove the banner, drop `robots` noindex in `src/app/exploit/page.tsx` and set
  `indexable: true` in `productSites.ts`; add it to the sitemap, footer and
  services page; update `src/app/exploit/page.test.tsx`, which currently fails
  if any of that happens.

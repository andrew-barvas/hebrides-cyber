// Product sub-sites served from their own subdomains by the same Next.js app.
//
// lookout.hebridescyber.co.uk is the /lookout page and exploit.hebridescyber.co.uk
// is the /exploit page; proxy.ts applies the routing below before anything else.
// One app rather than separate sites, so sign-in, the design system and the
// links into the platform are shared. Each product site is a single page: its
// root is rewritten to the product's path, a request for the product's own path
// is redirected to the clean root, and every other path (login, pricing, the
// dashboard) is redirected to the main site, where the session cookie lives.
//
// The hosts only answer once the owner has added the DNS records and the Azure
// Static Web Apps custom domains (docs/OWNER-TODO.md). Until then the pages are
// reachable at www.hebridescyber.co.uk/lookout and /exploit.

export type ProductSite = { host: string; path: string; indexable: boolean };

export const PRODUCT_SITES: readonly ProductSite[] = [
  { host: "lookout.hebridescyber.co.uk", path: "/lookout", indexable: true },
  // Not marketed until OT-13 (insurance and engagement contract) is signed off:
  // noindex on both its host and path, and nothing on the main site links to it.
  { host: "exploit.hebridescyber.co.uk", path: "/exploit", indexable: false },
];

const MAIN_SITE = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";

/** Absolute URL on the main site — product pages link into the platform with these, so a link works from either host. */
export function mainSiteUrl(path: string): string {
  return `${MAIN_SITE}${path}`;
}

/** `lookout.localhost:3000` maps to the same site as the production host, for local testing. */
function siteForHost(host: string | null): ProductSite | undefined {
  const name = (host ?? "").toLowerCase().replace(/:\d+$/, "");
  return PRODUCT_SITES.find((s) => name === s.host || name === `${s.path.slice(1)}.localhost`);
}

export type ProductSiteRoute =
  | { kind: "rewrite"; pathname: string; indexable: boolean }
  | { kind: "redirect"; url: string };

/** What to do with a request on a product host; null means it isn't one (serve as normal). */
export function routeProductSite(host: string | null, pathname: string, search = ""): ProductSiteRoute | null {
  const site = siteForHost(host);
  if (!site) return null;
  if (pathname === "/") return { kind: "rewrite", pathname: site.path, indexable: site.indexable };
  if (pathname === site.path || pathname === `${site.path}/`) return { kind: "redirect", url: `/${search}` };
  return { kind: "redirect", url: mainSiteUrl(`${pathname}${search}`) };
}

/** True for a product page that must stay out of search results, whichever host serves it. */
export function isNoindexPath(pathname: string): boolean {
  return PRODUCT_SITES.some((s) => !s.indexable && (pathname === s.path || pathname.startsWith(`${s.path}/`)));
}

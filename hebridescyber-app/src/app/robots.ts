import type { MetadataRoute } from "next";

// No robots.txt existed before this. Disallows exactly the routes that
// require auth or expose no independent SEO value (account-scoped or
// token-scoped pages a crawler could never usefully index anyway) — mirrors
// the private-vs-public route split docs/FUNCTIONALITY-MATRIX.md already
// documents for the API layer.
const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: "/",
      disallow: ["/dashboard", "/account", "/admin", "/auth", "/login", "/share", "/api"],
    },
    sitemap: `${SITE_URL}/sitemap.xml`,
  };
}

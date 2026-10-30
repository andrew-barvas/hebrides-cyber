import type { Metadata, Viewport } from "next";
import { Suspense } from "react";
import { headers } from "next/headers";
import { JetBrains_Mono } from "next/font/google";
import "./globals.css";
import Header from "@/components/Header";
import Footer from "@/components/Footer";
import CookieConsent from "@/components/CookieConsent";
import GoogleAnalytics from "@/components/GoogleAnalytics";

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "700"],
  variable: "--font-jetbrains-mono",
  display: "swap",
  preload: true,
});

// Used both by metadataBase below (so relative OG images/canonical URLs
// resolve to an absolute URL instead of silently falling back to
// localhost) and by the LocalBusiness JSON-LD in the body. Same fallback
// value as every other NEXT_PUBLIC_SITE_URL read in this codebase.
const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? "https://www.hebridescyber.co.uk";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: "Hebrides Cyber — Security Scanning & Penetration Testing, Stornoway, Scotland",
  description:
    "Automated security scanning, penetration testing, and CI/CD hardening for small businesses and SaaS teams. Based in Stornoway, Isle of Lewis, Scotland.",
  alternates: {
    types: {
      "application/rss+xml": `${SITE_URL}/feed.xml`,
    },
  },
  icons: {
    icon: "/favicon.svg",
    // Not named "apple-icon.png" — that exact filename is a reserved Next.js
    // metadata-route convention name even under public/, and 404s instead of
    // being served as a plain static file when there's no app/apple-icon.*
    // to back it (verified: icon-192.png/icon-512.png, which aren't reserved
    // names, serve fine from the same directory).
    apple: "/touch-icon-180.png",
  },
  openGraph: {
    siteName: "Hebrides Cyber",
    type: "website",
  },
  manifest: "/manifest.webmanifest",
};

// themeColor/colorScheme moved out of `metadata` into their own export in
// Next 14+ — matches the dark theme ThemeScript below defaults to (and
// src/app/manifest.ts's background_color/theme_color).
export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#070B14",
  colorScheme: "dark",
};

// Runs before React hydrates — reads saved preference from localStorage and
// applies the `dark` class to <html> immediately, preventing a flash of the
// wrong theme. Default is dark (cyber theme) unless the user has saved "light".
const ThemeScript = ({ nonce }: { nonce?: string }) => (
  <script
    nonce={nonce}
    dangerouslySetInnerHTML={{
      __html: `(function(){
  try {
    var t = localStorage.getItem('hc-theme');
    if (t === 'light') {
      document.documentElement.classList.remove('dark');
    } else {
      document.documentElement.classList.add('dark');
    }
  } catch(e) {
    document.documentElement.classList.add('dark');
  }
})();`,
    }}
  />
);

// LocalBusiness structured data — no equivalent existed before this. Local
// competitors (see docs/COMPETITIVE-ANALYSIS.md's Stornoway-based-competitor
// note) already establish location trust through years of backlinks/case
// studies; structured data is one of the few levers a brand-new site has to
// signal the same "genuinely local" fact to search engines from day one.
// addressLocality/addressRegion match this session's own domain work
// (hebridescyber.co.uk, wired up 2026-09-04) — keep in sync if the
// registered business address ever changes.
function LocalBusinessJsonLd() {
  const data = {
    "@context": "https://schema.org",
    "@type": "ProfessionalService",
    name: "Hebrides Cyber",
    description:
      "Automated security scanning, penetration testing, and CI/CD hardening for small businesses and SaaS teams.",
    url: SITE_URL,
    address: {
      "@type": "PostalAddress",
      addressLocality: "Stornoway",
      addressRegion: "Isle of Lewis",
      addressCountry: "GB",
    },
    areaServed: ["GB", "Scotland", "Outer Hebrides"],
    sameAs: [],
  };
  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }}
    />
  );
}

// async + headers(): the per-request CSP nonce (src/middleware.ts) is read here,
// which also opts every page into dynamic rendering — a nonce cannot be baked
// into a statically generated page.
export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  return (
    <html lang="en" className={jetbrainsMono.variable}>
      <head>
        <ThemeScript nonce={nonce} />
        <LocalBusinessJsonLd />
      </head>
      <body className="flex min-h-screen flex-col">
        {/* WCAG 2.4.1 — first tab stop skips the header nav. tabIndex=-1 on
            <main> makes focus actually move there in every browser, not
            just scroll. */}
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-neon focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-cyberbg"
        >
          Skip to main content
        </a>
        <Suspense fallback={null}>
          <GoogleAnalytics nonce={nonce} />
        </Suspense>
        <Header />
        <main id="main-content" tabIndex={-1} className="flex-1 focus:outline-hidden">
          {children}
        </main>
        <Footer />
        <CookieConsent />
      </body>
    </html>
  );
}

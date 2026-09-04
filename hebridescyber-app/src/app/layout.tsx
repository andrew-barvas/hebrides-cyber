import type { Metadata } from "next";
import { Suspense } from "react";
import { JetBrains_Mono } from "next/font/google";
import "./globals.css";
import Header from "@/components/Header";
import Footer from "@/components/Footer";
import CookieConsent from "@/components/CookieConsent";
import GoogleAnalytics from "@/components/GoogleAnalytics";

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "700"],
  variable: "--font-mono",
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
  icons: {
    icon: "/favicon.svg",
  },
  openGraph: {
    siteName: "Hebrides Cyber",
    type: "website",
  },
};

// Runs before React hydrates — reads saved preference from localStorage and
// applies the `dark` class to <html> immediately, preventing a flash of the
// wrong theme. Default is dark (cyber theme) unless the user has saved "light".
const ThemeScript = () => (
  <script
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

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={jetbrainsMono.variable}>
      <head>
        <ThemeScript />
        <LocalBusinessJsonLd />
      </head>
      <body className="flex min-h-screen flex-col">
        <Suspense fallback={null}>
          <GoogleAnalytics />
        </Suspense>
        <Header />
        <main className="flex-1">{children}</main>
        <Footer />
        <CookieConsent />
      </body>
    </html>
  );
}

import type { Metadata } from "next";
import { Suspense } from "react";
import { JetBrains_Mono } from "next/font/google";
import "./globals.css";
import Header from "@/components/Header";
import Footer from "@/components/Footer";
import CookieConsent from "@/components/CookieConsent";
import GoogleAnalytics from "@/components/GoogleAnalytics";

// Self-hosted via next/font (downloaded at build time, no external request
// at runtime — no third-party font CDN to add to a CSP later). Exposed as
// a CSS variable and wired to the `font-mono` Tailwind utility in
// tailwind.config.cjs, used for the "terminal" accents in the cyber theme.
const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "700"],
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: "Hebrides Cyber — Professional security for SaaS teams and growing businesses",
  description:
    "Automated security scanning, penetration testing, and CI/CD hardening for small businesses and SaaS teams. Based in the Isle of Lewis.",
  icons: {
    icon: "/favicon.svg",
  },
  openGraph: {
    siteName: "Hebrides Cyber",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={jetbrainsMono.variable}>
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

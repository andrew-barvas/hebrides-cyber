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

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={jetbrainsMono.variable}>
      <head>
        <ThemeScript />
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

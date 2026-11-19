import type { Metadata } from "next";

// Its own tab title (IMPROVEMENT-REVIEW-2026-11.md UX fix 5); an account page
// has nothing to rank for, so it stays out of search results.
export const metadata: Metadata = {
  title: "Integrations | Hebrides Cyber",
  robots: { index: false, follow: false },
};

export default function IntegrationsLayout({ children }: { children: React.ReactNode }) {
  return children;
}

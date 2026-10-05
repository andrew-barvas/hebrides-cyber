import type { Metadata } from "next";

// pricing/page.tsx is a client component and can't export metadata itself;
// without this the page (priority 0.9 in the sitemap) inherits the home page's
// title and description.
export const metadata: Metadata = {
  title: "Pricing — Security Scanning & Penetration Testing | Hebrides Cyber",
  description:
    "Simple pricing for automated security scanning, monitoring and expert penetration testing for small businesses and SaaS teams. Start with a free scan.",
  alternates: { canonical: "/pricing" },
};

export default function PricingLayout({ children }: { children: React.ReactNode }) {
  return children;
}

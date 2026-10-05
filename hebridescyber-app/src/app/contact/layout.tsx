import type { Metadata } from "next";

// contact/page.tsx is a client component, so its metadata lives here.
export const metadata: Metadata = {
  title: "Book a Free Security Score Scan | Hebrides Cyber",
  description:
    "Tell us about your site or app and we'll run a free Security Score scan with clear, prioritised fixes. Based in Stornoway, Isle of Lewis, serving the UK.",
  alternates: { canonical: "/contact" },
};

export default function ContactLayout({ children }: { children: React.ReactNode }) {
  return children;
}

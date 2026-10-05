import type { Metadata } from "next";

// An account page has nothing to rank for; keep it out of search results.
export const metadata: Metadata = {
  title: "Sign in | Hebrides Cyber",
  robots: { index: false, follow: false },
};

export default function LoginLayout({ children }: { children: React.ReactNode }) {
  return children;
}

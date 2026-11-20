import type { Metadata } from "next";

// Account pages have nothing to rank for. Exploit (P-07) is also not launched,
// so nothing links here: an engineer sends the customer the link once an
// engagement exists (docs/EXPLOIT-PRODUCT-PLAN.md, OT-13 / OT-51).
export const metadata: Metadata = {
  title: "Testing engagements | Hebrides Cyber",
  robots: { index: false, follow: false },
};

export default function EngagementsLayout({ children }: { children: React.ReactNode }) {
  return children;
}

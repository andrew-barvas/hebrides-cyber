import type { Metadata } from "next";

// A shared fix plan (src/lib/fixPlans.ts): reached only by its link, so it
// stays out of search results, like a shared report.
export const metadata: Metadata = {
  title: "Fix plan | Hebrides Cyber",
  robots: { index: false, follow: false },
};

export default function PlanLayout({ children }: { children: React.ReactNode }) {
  return children;
}

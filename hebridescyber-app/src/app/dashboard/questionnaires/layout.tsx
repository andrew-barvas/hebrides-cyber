import type { Metadata } from "next";

// An account page has nothing to rank for, so it stays out of search results.
export const metadata: Metadata = {
  title: "Questionnaires | Hebrides Cyber",
  robots: { index: false, follow: false },
};

export default function QuestionnairesLayout({ children }: { children: React.ReactNode }) {
  return children;
}

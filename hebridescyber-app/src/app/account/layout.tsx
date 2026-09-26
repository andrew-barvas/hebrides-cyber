import type { Metadata } from "next";
import AppShell from "@/components/app-shell/AppShell";

export const metadata: Metadata = {
  title: "Account · Hebrides Cyber",
  robots: { index: false, follow: false },
};

export default function AccountLayout({ children }: { children: React.ReactNode }) {
  return <AppShell>{children}</AppShell>;
}

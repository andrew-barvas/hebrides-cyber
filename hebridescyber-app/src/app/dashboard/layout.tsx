import type { Metadata } from "next";
import AppShell from "@/components/app-shell/AppShell";

export const metadata: Metadata = {
  title: "Dashboard · Hebrides Cyber",
  robots: { index: false, follow: false },
};

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return <AppShell>{children}</AppShell>;
}

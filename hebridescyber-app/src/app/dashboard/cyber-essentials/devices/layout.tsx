import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Devices | Hebrides Cyber",
  robots: { index: false, follow: false },
};

export default function DevicesLayout({ children }: { children: React.ReactNode }) {
  return children;
}

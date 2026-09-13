"use client";

import Link from "next/link";
import AssetInventory from "@/components/AssetInventory";

export default function AssetsPage() {
  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      <div className="bg-grid pointer-events-none fixed inset-0 opacity-20" />
      <div className="relative mx-auto max-w-4xl px-4 py-10 sm:px-6 space-y-6">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="font-mono text-xs text-neon/50" aria-hidden="true">$ ./assets --inventory</p>
            <h1 className="text-2xl font-bold text-cybertext sm:text-3xl">Asset Inventory</h1>
          </div>
          <Link
            href="/dashboard"
            className="rounded-md border border-cyberborder px-4 py-2 text-sm font-medium text-cybertext/70 hover:border-neon hover:text-neon transition-colors"
          >
            ← Dashboard
          </Link>
        </div>
        <p className="text-sm text-cybertext/50">
          Domains and subdomains discovered across your scans, with detected CMS and cloud/CDN hints.
        </p>
        <AssetInventory />
      </div>
    </div>
  );
}

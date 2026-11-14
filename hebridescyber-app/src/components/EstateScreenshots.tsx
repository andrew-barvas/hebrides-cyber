"use client";

// Owner-only, on the scan report: screenshots of every live web host the scan
// found (src/lib/estateScreenshots.ts). The API takes a Bearer token, which an
// <img> can't send, so each image is fetched and shown through a blob: URL
// (allowed by the CSP's img-src). Renders nothing when there are none.
import { useEffect, useState } from "react";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

type Shot = { host: string; src: string };

export default function EstateScreenshots({ scanId, token }: { scanId: string; token: string }) {
  const [shots, setShots] = useState<Shot[] | null>(null);

  useEffect(() => {
    let cancelled = false;
    const urls: string[] = [];
    (async () => {
      const res = await fetch(`/api/scans/${scanId}/screenshots`, { headers: { Authorization: `Bearer ${token}` } }).catch(() => null);
      if (!res?.ok) return;
      const body = (await res.json()) as { items?: Array<{ host: string; file: string }> };
      const loaded: Shot[] = [];
      for (const item of body.items ?? []) {
        const img = await fetch(`/api/scans/${scanId}/screenshots/${encodeURIComponent(item.file)}`, { headers: { Authorization: `Bearer ${token}` } }).catch(() => null);
        if (!img?.ok) continue;
        const url = URL.createObjectURL(await img.blob());
        urls.push(url);
        loaded.push({ host: item.host, src: url });
      }
      if (!cancelled) setShots(loaded);
    })();
    return () => {
      cancelled = true;
      urls.forEach((u) => URL.revokeObjectURL(u));
    };
  }, [scanId, token]);

  if (!shots || shots.length === 0) return null;

  return (
    <Card className="print:break-inside-avoid">
      <CardHeader>
        <div className="min-w-0">
          <CardTitle as="h2">your sites at a glance</CardTitle>
          <CardDescription className="mt-1">
            Every live website we found for this domain, as it looked during the scan. Look for anything you don&apos;t recognise, a default server page or a login screen that shouldn&apos;t be public.
          </CardDescription>
        </div>
      </CardHeader>
      <ul className="grid gap-4 sm:grid-cols-2">
        {shots.map((s) => (
          <li key={s.host}>
            {/* eslint-disable-next-line @next/next/no-img-element -- a blob: URL from an authenticated fetch */}
            <img src={s.src} alt={`Screenshot of ${s.host}`} className="w-full rounded-md border border-cyberborder" loading="lazy" />
            <p className="mt-1 break-all text-xs text-cybermuted">{s.host}</p>
          </li>
        ))}
      </ul>
    </Card>
  );
}

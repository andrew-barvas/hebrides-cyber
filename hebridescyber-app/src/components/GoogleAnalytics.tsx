"use client";

import { useEffect } from "react";
import Script from "next/script";
import { usePathname, useSearchParams } from "next/navigation";
import { getStoredConsent } from "./CookieConsent";

declare global {
  interface Window {
    dataLayer: unknown[];
    gtag: (...args: unknown[]) => void;
  }
}

const measurementId = process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID;

/**
 * Loads gtag.js and fires page_view on route change. Only mounts the
 * script tags at all if the user has accepted the cookie banner
 * (CookieConsent.tsx) — GA4 sets cookies, which are non-essential under
 * UK/EU rules and need opt-in consent first.
 *
 * App Router doesn't fire a browser navigation event on client-side route
 * changes (it's an SPA under the hood), so gtag's automatic page_view on
 * script load only catches the very first page — the pathname/searchParams
 * effect below sends the rest manually.
 */
export default function GoogleAnalytics({ nonce }: { nonce?: string }) {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  useEffect(() => {
    if (!measurementId || typeof window.gtag !== "function") return;
    const url = pathname + (searchParams?.toString() ? `?${searchParams.toString()}` : "");
    window.gtag("event", "page_view", { page_path: url });
  }, [pathname, searchParams]);

  if (!measurementId || getStoredConsent() !== "accepted") {
    // TODO: if you add more cookie categories later, this all-or-nothing
    // check (consent === "accepted") won't be granular enough — move to
    // per-category consent state at that point.
    return null;
  }

  return (
    <>
      <Script src={`https://www.googletagmanager.com/gtag/js?id=${measurementId}`} strategy="afterInteractive" nonce={nonce} />
      <Script id="ga4-init" strategy="afterInteractive" nonce={nonce}>
        {`
          window.dataLayer = window.dataLayer || [];
          function gtag(){dataLayer.push(arguments);}
          window.gtag = gtag;
          gtag('js', new Date());
          gtag('config', '${measurementId}', { anonymize_ip: true });
        `}
      </Script>
    </>
  );
}

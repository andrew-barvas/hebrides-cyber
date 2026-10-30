"use client";

import { useEffect, useState } from "react";

const STORAGE_KEY = "hebridescyber-cookie-consent"; // "accepted" | "declined"

export function getStoredConsent(): "accepted" | "declined" | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(STORAGE_KEY) as "accepted" | "declined" | null;
}

// The cookies Google Analytics 4 writes: _ga, one _ga_<measurement id> per
// property, and the legacy _gid / _gat family. Anything else (a session or
// preference cookie) must survive a withdrawal, so this is an allow-list of
// names to delete, never "clear everything".
const ANALYTICS_COOKIE_RE = /^(_ga(_[A-Za-z0-9]+)?|_gid|_gat(_.+)?)$/;

/**
 * Deletes the analytics cookies this site's visitor already has. GA writes
 * them on the registrable domain (e.g. .hebridescyber.co.uk) rather than the
 * exact host, and a cookie can only be removed with the same domain and path
 * it was set with, so each parent domain of the current host is tried as well
 * as the host itself. A browser silently ignores a domain it won't allow
 * (such as a public suffix), so the extra attempts are harmless.
 */
export function clearAnalyticsCookies(): void {
  if (typeof document === "undefined") return;
  const names = document.cookie
    .split(";")
    .map((pair) => pair.split("=")[0].trim())
    .filter((name) => ANALYTICS_COOKIE_RE.test(name));
  if (names.length === 0) return;

  const labels = window.location.hostname.split(".");
  const domains = labels.map((_, i) => labels.slice(i).join(".")).filter((d) => d.includes("."));
  const expired = "expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
  for (const name of names) {
    document.cookie = `${name}=; ${expired}`;
    for (const domain of domains) {
      document.cookie = `${name}=; ${expired}; domain=${domain}`;
      document.cookie = `${name}=; ${expired}; domain=.${domain}`;
    }
  }
}

/**
 * Withdraws consent: forgets the stored choice and removes the analytics
 * cookies already set. The caller reloads the page afterwards, which brings
 * the banner back and stops GoogleAnalytics.tsx mounting its scripts (it only
 * does so when the stored choice is "accepted").
 */
export function withdrawConsent(): void {
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage blocked: there is nothing stored to forget, so carry on and
    // still remove the cookies.
  }
  clearAnalyticsCookies();
}

/**
 * The footer's "Cookie settings" control. The privacy policy promises visitors
 * they can withdraw consent from the footer; this is that control. It resets
 * the choice (rather than silently declining) so the visitor is asked again.
 */
export function CookieSettingsButton({ className }: { className?: string }) {
  return (
    <button
      type="button"
      className={className}
      onClick={() => {
        withdrawConsent();
        window.location.reload();
      }}
    >
      Cookie settings
    </button>
  );
}

// UK/GDPR: analytics cookies are non-essential and require opt-in consent
// BEFORE they're set — GoogleAnalytics.tsx checks getStoredConsent() and
// only loads gtag.js after "accepted" is stored here. A simple accept/
// decline banner, not a full preference-center — fine for a single
// analytics vendor, revisit if more cookie categories get added later.
export default function CookieConsent() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    setVisible(getStoredConsent() === null);
  }, []);

  function choose(choice: "accepted" | "declined") {
    window.localStorage.setItem(STORAGE_KEY, choice);
    setVisible(false);
    // Reload so GoogleAnalytics.tsx picks up the new consent state on next
    // mount rather than needing its own storage-event listener.
    if (choice === "accepted") window.location.reload();
  }

  if (!visible) return null;

  return (
    // Deliberately a fixed light surface in both themes, so it needs an
    // explicit text colour — without it the buttons inherit the body colour,
    // which is white in dark mode and vanishes against the white banner.
    <div className="fixed inset-x-0 bottom-0 z-50 flex flex-col items-center justify-between gap-3 border-t border-slate-200 bg-white p-4 text-sm text-slatedark shadow-lg sm:flex-row">
      <p className="text-slatedark/80">
        We use analytics cookies to understand site usage. See our{" "}
        <a href="/privacy" className="underline">
          privacy policy
        </a>
        .
      </p>
      <div className="flex shrink-0 gap-2">
        <button onClick={() => choose("declined")} className="rounded-md border border-slate-300 px-4 py-2 font-medium hover:bg-slate-50">
          Decline
        </button>
        <button onClick={() => choose("accepted")} className="rounded-md bg-atlantic px-4 py-2 font-medium text-white hover:opacity-90">
          Accept
        </button>
      </div>
    </div>
  );
}

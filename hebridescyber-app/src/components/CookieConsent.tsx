"use client";

import { useEffect, useState } from "react";

const STORAGE_KEY = "hebridescyber-cookie-consent"; // "accepted" | "declined"

export function getStoredConsent(): "accepted" | "declined" | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(STORAGE_KEY) as "accepted" | "declined" | null;
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
    <div className="fixed inset-x-0 bottom-0 z-50 flex flex-col items-center justify-between gap-3 border-t border-slate-200 bg-white p-4 text-sm shadow-lg sm:flex-row">
      <p className="text-slatedark/80">
        We use analytics cookies to understand site usage. See our{" "}
        <a href="/privacy" className="underline">
          privacy policy
        </a>
        . {/* TODO: /privacy doesn't exist yet — add a real privacy policy page before launch. */}
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

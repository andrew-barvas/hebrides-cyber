"use client";

import { useEffect, useState } from "react";
import { supabase } from "./supabaseClient";

/**
 * The current Supabase access token, kept fresh for the lifetime of the page.
 *
 * Exists because reading the token once on mount is a real bug, not a
 * simplification. Supabase access tokens expire after an hour. supabase-js
 * refreshes them in the background (and on tab focus) and stores the new one,
 * but a component that did:
 *
 *     useEffect(() => { getSession().then(s => setToken(s?.access_token)) }, [])
 *
 * captures the token as it was at mount and never hears about the refresh. On
 * a page left open for a few hours the UI still looks signed in — the session
 * genuinely is valid — while every button that sends that captured token gets
 * a 401. Subscribing to onAuthStateChange is what closes that gap: it fires on
 * TOKEN_REFRESHED, so the token in state tracks the real one.
 *
 * Returns null while the initial lookup is in flight and after sign-out, so
 * callers should treat null as "not ready / not authenticated" rather than
 * assuming a string.
 *
 * Prefer this over calling getSession() at mount. Calling getSession() inside
 * the click handler itself is also correct (it refreshes on demand) — that's
 * what src/app/dashboard/page.tsx and src/components/DomainVerification.tsx
 * do. This hook is for the case where the token has to be held in state to be
 * passed down as a prop.
 */
export function useSessionToken(): string | null {
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    supabase.auth.getSession().then(({ data }) => {
      if (active) setToken(data.session?.access_token ?? null);
    });
    const { data: subscription } = supabase.auth.onAuthStateChange((_event, session) => {
      if (active) setToken(session?.access_token ?? null);
    });
    return () => {
      active = false;
      subscription.subscription.unsubscribe();
    };
  }, []);

  return token;
}

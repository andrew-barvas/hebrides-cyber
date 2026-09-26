"use client";

import { useCallback, useState } from "react";
import { getSession } from "@/lib/auth";

/** Opens the Stripe customer portal. Fetches a fresh access token at click
 *  time rather than taking one as an argument — a token captured when the
 *  page loaded can be an hour stale by the time someone clicks. */
export function useBillingPortal() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const open = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const session = await getSession();
      if (!session) throw new Error("Your session has expired — sign in again.");
      const res = await fetch("/api/stripe/customer-portal", {
        method: "POST",
        headers: { Authorization: `Bearer ${session.access_token}` },
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not open the billing portal.");
      window.location.href = body.url;
    } catch (err) {
      setError((err as Error).message);
      setLoading(false);
    }
  }, []);

  return { open, loading, error };
}

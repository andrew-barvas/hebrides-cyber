"use client";

// Which hostnames the signed-in user has verified, so the Run scan form can
// say "verify this first" before the user waits for a refusal. The server
// (run-scan.ts via ownership.ts's isDomainVerified) stays the authority;
// this is only a hint. Verification is per exact hostname, so example.com
// and www.example.com are different, which is worth pointing out.
import { useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";

export type VerifiedDomains = { domains: Set<string>; isAdmin: boolean; loaded: boolean };

export function useVerifiedDomains(): VerifiedDomains {
  const [state, setState] = useState<VerifiedDomains>({ domains: new Set(), isAdmin: false, loaded: false });
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const [verified, user] = await Promise.all([
        supabase.from("verifications").select("domain").not("verified_at", "is", null),
        supabase.from("users").select("is_admin").maybeSingle(),
      ]);
      if (cancelled) return;
      setState({
        domains: new Set(((verified.data ?? []) as { domain: string }[]).map((v) => v.domain.toLowerCase())),
        isAdmin: Boolean((user.data as { is_admin?: boolean } | null)?.is_admin),
        // A failed read gives no hint rather than a wrong one.
        loaded: !verified.error,
      });
    })();
    return () => {
      cancelled = true;
    };
  }, []);
  return state;
}

export type ScanTargetHint = { host: string; verifiedAlternative: string | null };

/** Pure: a hint when the URL's host isn't verified (admins are exempt), else null. */
export function scanTargetHint(targetUrl: string, verified: VerifiedDomains): ScanTargetHint | null {
  if (!verified.loaded || verified.isAdmin) return null;
  let host: string;
  try {
    host = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    return null;
  }
  if (!host || verified.domains.has(host)) return null;
  const twin = host.startsWith("www.") ? host.slice(4) : `www.${host}`;
  return { host, verifiedAlternative: verified.domains.has(twin) ? twin : null };
}

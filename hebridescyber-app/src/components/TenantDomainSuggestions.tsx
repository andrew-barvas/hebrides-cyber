"use client";

// "Domains from your Microsoft 365" on the Assets page (tenantDomains.ts):
// the connected tenant's verified domains that have no monitored site yet,
// with one-click add. Renders nothing unless a tenant is connected and the
// plan allows it, so it never nags. Adding inserts a monitored site exactly
// as typing it would (the plan cap still applies under RLS), and scanning
// still needs the domain verified.
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { TenantDomainsResult } from "@/lib/tenantDomains";

/** MonitoredTargets listens for this to reload after a site is added elsewhere on the page. */
export const MONITORED_TARGETS_CHANGED = "hc:monitored-targets-changed";

export default function TenantDomainSuggestions({ token }: { token: string | null }) {
  const [result, setResult] = useState<TenantDomainsResult | null>(null);
  const [adding, setAdding] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetch("/api/account/tenant-domains", { headers: { Authorization: `Bearer ${token}` } });
      setResult(res.ok ? ((await res.json()) as TenantDomainsResult) : null);
    } catch {
      setResult(null);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  if (!result || result.status === "not_connected" || result.status === "not_configured") return null;

  if (result.status === "error") {
    return (
      <Card>
        <CardTitle>domains from your microsoft 365</CardTitle>
        <p className="mt-2 text-sm text-cybermuted">{result.message}</p>
      </Card>
    );
  }

  const missing = result.domains.filter((d) => !d.monitored);
  if (result.domains.length === 0) return null;

  async function add(domain: string) {
    setAdding(domain);
    setMessage(null);
    const {
      data: { user },
    } = await supabase.auth.getUser();
    if (!user) {
      setAdding(null);
      return;
    }
    const { error } = await supabase.from("monitored_targets").insert({ owner: user.id, target_url: `https://${domain}` });
    setAdding(null);
    if (error) {
      setMessage(error.code === "42501" ? "You've reached your plan's limit of monitored sites. Upgrade your plan or remove one to add this." : "Couldn't add it just now. Try again, or add it by hand above.");
      return;
    }
    setMessage(`Added ${domain}. Verify you own it (top of this page) and it will be scanned on your schedule.`);
    window.dispatchEvent(new Event(MONITORED_TARGETS_CHANGED));
    await load();
  }

  return (
    <Card aria-labelledby="tenant-domains-heading">
      <CardHeader>
        <div>
          <CardTitle id="tenant-domains-heading">domains from your microsoft 365</CardTitle>
          <CardDescription className="mt-1">
            Domains your Microsoft 365 has verified for email. {missing.length === 0 ? "Every one is already covered by a monitored site." : "These have no monitored site yet, so nothing is watching them."}
          </CardDescription>
        </div>
      </CardHeader>
      {missing.length > 0 && (
        <ul className="divide-y divide-cyberborder rounded-lg border border-cyberborder">
          {missing.map((d) => (
            <li key={d.domain} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
              <span className="font-mono text-sm text-cybertext break-all">{d.domain}</span>
              <Button size="sm" variant="secondary" disabled={adding !== null} onClick={() => add(d.domain)}>
                {adding === d.domain ? "Adding…" : "Add as a monitored site"}
                {" "}
                <span className="sr-only">for {d.domain}</span>
              </Button>
            </li>
          ))}
        </ul>
      )}
      {message && (
        <p role="status" className="mt-3 text-sm text-cybertext">
          {message}
        </p>
      )}
      {result.truncated && <p className="mt-2 text-xs text-cybermuted">Showing the first 500 domains from your tenant.</p>}
      <p className="mt-3 text-xs text-cybermuted">
        Read live from your tenant with the read-only access you granted under <Link href="/dashboard/integrations" className="text-neon hover:underline">Integrations</Link>; we don&apos;t store the list.
      </p>
    </Card>
  );
}

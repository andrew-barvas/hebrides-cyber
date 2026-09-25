"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";
import { getSession } from "@/lib/auth";
import ApiKeys from "@/components/ApiKeys";
import Webhooks from "@/components/Webhooks";
import RequestAudit from "@/components/RequestAudit";
import ConnectRepo from "@/components/ConnectRepo";
import TicketIntegration from "@/components/TicketIntegration";
import OncallIntegrationConfig from "@/components/OncallIntegrationConfig";
import TeamSection from "@/components/TeamSection";
import TwoFactor from "@/components/TwoFactor";
import BrandingSection from "@/components/BrandingSection";
import AccountDeletion from "@/components/AccountDeletion";
import ApiSpecConfig from "@/components/ApiSpecConfig";

type Plan = "none" | "basic" | "pro" | "agency";

const PLAN_LABELS: Record<string, string> = {
  none: "No plan",
  basic: "Basic",
  pro: "Pro",
  agency: "Agency",
};

export default function AccountPage() {
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [userId, setUserId] = useState<string | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [plan, setPlan] = useState<Plan>("none");
  const [planStatus, setPlanStatus] = useState<string | null>(null);
  const [brandLogoUrl, setBrandLogoUrl] = useState<string | null>(null);
  const [brandName, setBrandName] = useState<string | null>(null);
  const [portalLoading, setPortalLoading] = useState(false);
  const [portalError, setPortalError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const session = await getSession();
    setAuthed(Boolean(session));
    if (!session) return;

    setEmail(session.user.email ?? null);
    setUserId(session.user.id);
    setToken(session.access_token);

    const { data } = await supabase
      .from("subscriptions")
      .select("plan, status, brand_logo_url, brand_name")
      .maybeSingle();

    if (data) {
      setPlan(data.plan as Plan);
      setPlanStatus(data.status as string);
      setBrandLogoUrl((data.brand_logo_url as string | null) ?? null);
      setBrandName((data.brand_name as string | null) ?? null);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function openBillingPortal() {
    setPortalLoading(true);
    setPortalError(null);
    try {
      const res = await fetch("/api/stripe/customer-portal", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not open billing portal");
      window.location.href = body.url;
    } catch (err) {
      setPortalError((err as Error).message);
      setPortalLoading(false);
    }
  }

  if (authed === null) {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center">
        <p className="font-mono text-sm text-cybertext/30">// loading account…</p>
      </div>
    );
  }

  if (!authed) {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center text-center px-6">
        <div>
          <p className="font-mono text-sm text-neon mb-2">$ auth --required</p>
          <h1 className="text-xl font-bold text-cybertext mb-4">Sign in to view your account</h1>
          <Link href="/login" className="text-neon underline">Sign in</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      <div className="bg-grid pointer-events-none fixed inset-0 opacity-20" />

      <div className="relative mx-auto max-w-3xl px-4 py-10 sm:px-6 space-y-8">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="font-mono text-xs text-neon/50" aria-hidden="true">$ ./account</p>
            <h1 className="text-2xl font-bold text-cybertext sm:text-3xl">My account</h1>
          </div>
          <Link
            href="/dashboard"
            className="rounded-md border border-cyberborder px-4 py-2 text-sm font-medium text-cybertext/70 hover:border-neon hover:text-neon transition-colors"
          >
            ← Dashboard
          </Link>
        </div>

        {/* Profile */}
        <section className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
          <h2 className="font-mono text-xs text-cybertext/40 uppercase tracking-wide mb-4">// profile</h2>
          <dl className="space-y-3 text-sm">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <dt className="text-cybertext/50">Email</dt>
              <dd className="font-mono text-neon/80 break-all">{email}</dd>
            </div>
          </dl>
          <p className="mt-4 text-xs text-cybertext/40">
            Signing in uses this address. To change it, contact us — we&apos;ll move your
            scans and subscription across.
          </p>
        </section>

        {/* Plan & billing */}
        <section className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
          <h2 className="font-mono text-xs text-cybertext/40 uppercase tracking-wide mb-4">// plan &amp; billing</h2>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="text-lg font-bold text-neon">{PLAN_LABELS[plan] ?? plan}</p>
              {planStatus === "past_due" && (
                <p className="mt-1 text-xs text-amber-400">
                  Payment past due — update your card to avoid losing access.
                </p>
              )}
              {plan === "none" && (
                <p className="mt-1 text-xs text-cybertext/40">
                  You&apos;re on the free tier.{" "}
                  <Link href="/pricing" className="text-neon hover:underline">Compare plans</Link>
                </p>
              )}
            </div>
            {plan !== "none" && (
              <button
                onClick={openBillingPortal}
                disabled={portalLoading}
                className="rounded-md border border-cyberborder px-4 py-2 text-sm font-medium text-cybertext/70 hover:border-neon hover:text-neon disabled:opacity-40 transition-colors"
              >
                {portalLoading ? "Opening…" : "Manage billing"}
              </button>
            )}
          </div>
          {portalError && (
            <p className="mt-3 text-xs text-red-400" role="alert">{portalError}</p>
          )}
        </section>

        {/* White-label branding (Agency plan only) */}
        {token && plan === "agency" && (
          <BrandingSection token={token} initialLogoUrl={brandLogoUrl} initialBrandName={brandName} />
        )}

        {/* One-off audit requests */}
        {token && <RequestAudit token={token} />}

        {/* API keys */}
        {token && <ApiKeys token={token} />}

        {/* Webhooks */}
        {token && <Webhooks token={token} />}

        {/* Connect a repository (dependency manifest scanning) */}
        <ConnectRepo />

        {/* API spec scanning */}
        <ApiSpecConfig />

        {/* Ticket integration (Jira/Linear) */}
        <TicketIntegration />

        {/* On-call alerting (PagerDuty/Opsgenie) */}
        <OncallIntegrationConfig />

        {/* Team */}
        {token && userId && <TeamSection token={token} currentUserId={userId} />}

        {/* Security */}
        <TwoFactor />

        {/* Danger zone */}
        {token && <AccountDeletion token={token} />}
      </div>
    </div>
  );
}

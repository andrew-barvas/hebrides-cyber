"use client";

// The logged-in app frame shared by /dashboard/* and /account: sidebar (lg+)
// or scrolling section tabs (below lg), plus one session/subscription load
// that every page inside reads via useAppSession() instead of each page
// re-fetching it. Because Next keeps a layout mounted across navigations
// between its child routes, moving between dashboard sections no longer
// re-runs the auth + subscription round-trips.
//
// Authentication itself is enforced server-side by src/middleware.ts; the
// signed-out branch here only covers a session that expires mid-visit. The
// MFA (AAL2) step-up check is NOT something middleware does, and used to run
// on /dashboard alone — /account and every /dashboard/* sub-page skipped it.
// Living here, it now covers every route this shell wraps.

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Lock } from "lucide-react";
import { supabase } from "@/lib/supabaseClient";
import { getSession, getMfaAssuranceLevel } from "@/lib/auth";
import type { Plan } from "@/components/PlanUpsell";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { CLIENT_STORAGE_KEY, parseScope, SCOPE_ALL, type ClientScope, type ClientSummary } from "@/lib/clientRollup";
import { AppMobileNav, AppSidebar } from "./AppNav";
import ClientSwitcher from "./ClientSwitcher";

export type AppSession = {
  userId: string;
  email: string | null;
  accessToken: string;
  /** For feature gating: the stored plan only while the subscription is
   *  active, otherwise "none" — a past_due Pro account loses Pro features,
   *  exactly as the dashboard has always behaved. */
  plan: Plan;
  /** The plan as stored regardless of status — for billing display, so a
   *  past_due account still sees which plan it's paying for. */
  billingPlan: Plan;
  planStatus: string | null;
  slackWebhookUrl: string;
  teamsWebhookUrl: string;
  refreshSubscription: () => Promise<void>;
  /** Agency client workspaces (empty for other plans). */
  clients: ClientSummary[];
  /** The switcher's selection; pages filter their data by it. */
  currentClientId: ClientScope;
  setCurrentClientId: (scope: ClientScope) => void;
  refreshClients: () => Promise<void>;
};

const AppSessionContext = createContext<AppSession | null>(null);

export function useAppSession(): AppSession {
  const ctx = useContext(AppSessionContext);
  if (!ctx) throw new Error("useAppSession() must be called inside <AppShell>");
  return ctx;
}

type Identity = { userId: string; email: string | null; accessToken: string };
type Subscription = { billingPlan: Plan; planStatus: string | null; slackWebhookUrl: string; teamsWebhookUrl: string };

export function effectivePlan(billingPlan: Plan, planStatus: string | null): Plan {
  return planStatus === "active" ? billingPlan : "none";
}

export default function AppShell({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname() ?? "/dashboard";
  const [status, setStatus] = useState<"loading" | "signed-out" | "ready">("loading");
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [sub, setSub] = useState<Subscription | null>(null);
  const [clients, setClients] = useState<ClientSummary[]>([]);
  const [clientsLoaded, setClientsLoaded] = useState(false);
  const [scope, setScope] = useState<ClientScope>(SCOPE_ALL);
  const agency = sub ? ["agency", "tier_a"].includes(effectivePlan(sub.billingPlan, sub.planStatus)) : false;

  const refreshClients = useCallback(async () => {
    try {
      const { data } = await supabase.from("clients").select("id, name").order("name", { ascending: true });
      setClients((data ?? []) as ClientSummary[]);
    } catch {
      setClients([]);
    }
    setClientsLoaded(true);
  }, []);

  const setCurrentClientId = useCallback((next: ClientScope) => {
    setScope(next);
    try {
      window.localStorage.setItem(CLIENT_STORAGE_KEY, next);
      const url = new URL(window.location.href);
      if (next === SCOPE_ALL) url.searchParams.delete("client");
      else url.searchParams.set("client", next);
      window.history.replaceState(null, "", url);
    } catch {
      // Private mode / blocked storage: the selection just won't persist.
    }
  }, []);

  // Agency only: load the clients once the plan is known.
  useEffect(() => {
    if (agency) void refreshClients();
  }, [agency, refreshClients]);

  // Restore the selection (URL param wins over localStorage) once clients are known,
  // dropping a stale id whose client has been deleted.
  useEffect(() => {
    if (!clientsLoaded) return;
    let raw: string | null = null;
    try {
      raw = new URLSearchParams(window.location.search).get("client") ?? window.localStorage.getItem(CLIENT_STORAGE_KEY);
    } catch {
      raw = null;
    }
    setScope(parseScope(raw, clients));
  }, [clientsLoaded, clients]);

  const refreshSubscription = useCallback(async () => {
    const { data } = await supabase
      .from("subscriptions")
      .select("plan, status, slack_webhook_url, ms_teams_webhook_url")
      .maybeSingle();
    setSub({
      billingPlan: ((data?.plan as Plan | undefined) ?? "none"),
      planStatus: (data?.status as string | undefined) ?? null,
      slackWebhookUrl: (data?.slack_webhook_url as string | null) ?? "",
      teamsWebhookUrl: (data?.ms_teams_webhook_url as string | null) ?? "",
    });
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const session = await getSession();
      if (!session) {
        if (!cancelled) setStatus("signed-out");
        return;
      }
      const { currentLevel, nextLevel } = await getMfaAssuranceLevel();
      if (nextLevel && currentLevel !== nextLevel) {
        router.replace("/login/mfa-challenge");
        return;
      }
      await refreshSubscription();
      if (cancelled) return;
      setIdentity({ userId: session.user.id, email: session.user.email ?? null, accessToken: session.access_token });
      setStatus("ready");
    })().catch((err) => {
      console.error("[app-shell] init error:", (err as Error).message);
      if (!cancelled) setStatus("signed-out");
    });
    return () => {
      cancelled = true;
    };
  }, [router, refreshSubscription]);

  const value = useMemo<AppSession | null>(() => {
    if (!identity || !sub) return null;
    return {
      ...identity,
      ...sub,
      plan: effectivePlan(sub.billingPlan, sub.planStatus),
      refreshSubscription,
      clients,
      currentClientId: scope,
      setCurrentClientId,
      refreshClients,
    };
  }, [identity, sub, refreshSubscription, clients, scope, setCurrentClientId, refreshClients]);

  const summary = sub ? { plan: effectivePlan(sub.billingPlan, sub.planStatus), billingPlan: sub.billingPlan, planStatus: sub.planStatus } : null;

  return (
    <div className="relative bg-cyberbg text-cybertext print:bg-white">
      <div className="bg-grid pointer-events-none absolute inset-0 opacity-20 print:hidden" aria-hidden="true" />
      <div className="relative mx-auto flex max-w-6xl gap-8 px-4 py-6 sm:px-6 lg:py-10 print:block print:max-w-none print:p-0">
        <AppSidebar summary={summary} className="hidden lg:block print:hidden" />
        <div className="min-w-0 flex-1">
          <AppMobileNav className="mb-6 lg:hidden print:hidden" />
          {status === "ready" && agency && clients.length > 0 && (
            <ClientSwitcher clients={clients} value={scope} onChange={setCurrentClientId} className="mb-6 print:hidden" />
          )}
          {status === "loading" && <ShellLoading />}
          {status === "signed-out" && (
            <EmptyState
              icon={<Lock />}
              title="Your session has ended"
              description="Sign in again to pick up where you left off."
              action={
                <Button asChild>
                  <Link href={`/login?redirect=${encodeURIComponent(pathname)}`}>Sign in</Link>
                </Button>
              }
            />
          )}
          {status === "ready" && value && <AppSessionContext.Provider value={value}>{children}</AppSessionContext.Provider>}
        </div>
      </div>
    </div>
  );
}

function ShellLoading() {
  return (
    <div className="space-y-6" aria-busy="true">
      <p className="sr-only" role="status">
        Loading…
      </p>
      <Skeleton className="h-9 w-48" />
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-28 rounded-xl" />
        ))}
      </div>
      <Skeleton className="h-64 rounded-xl" />
    </div>
  );
}

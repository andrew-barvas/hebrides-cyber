"use client";

import { useEffect, useState, useCallback, Suspense } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { supabase } from "@/lib/supabaseClient";
import { getSession, getMfaAssuranceLevel } from "@/lib/auth";
import ScanList, { Scan } from "@/components/ScanList";
import PlanUpsell, { Plan } from "@/components/PlanUpsell";
import DomainVerification from "@/components/DomainVerification";
import MonitoredTargets from "@/components/MonitoredTargets";

const PLAN_LABELS: Record<string, string> = {
  basic: "Basic — £20/mo",
  pro: "Pro — £35/mo",
  agency: "Agency — £75/mo",
};

// Isolated to its own component so Next.js 15+ Suspense requirement for
// useSearchParams() is satisfied without wrapping the entire page.
function CheckoutBanner() {
  const searchParams = useSearchParams();
  const result = searchParams?.get("checkout") ?? null;
  if (!result) return null;
  if (result === "success") {
    return (
      <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-800">
        <strong>Subscription activated!</strong> Your first automated scan will run within 24 hours. Welcome aboard.
      </div>
    );
  }
  if (result === "cancelled") {
    return (
      <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-700">
        Checkout cancelled — your plan hasn&apos;t changed.{" "}
        <Link href="/pricing" className="underline">View plans</Link>
      </div>
    );
  }
  return null;
}

export default function DashboardPage() {
  const router = useRouter();

  const [loading, setLoading] = useState(true);
  const [authed, setAuthed] = useState(false);
  const [scans, setScans] = useState<Scan[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [plan, setPlan] = useState<Plan>("none");
  const [planStatus, setPlanStatus] = useState<string | null>(null);
  const [slackWebhookUrl, setSlackWebhookUrl] = useState("");
  const [slackSaving, setSlackSaving] = useState(false);
  const [slackMessage, setSlackMessage] = useState<string | null>(null);
  const [portalLoading, setPortalLoading] = useState(false);

  const [targetUrl, setTargetUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);

  const loadPlan = useCallback(async () => {
    const { data } = await supabase
      .from("subscriptions")
      .select("plan, status, slack_webhook_url")
      .maybeSingle();
    if (data?.status === "active") {
      setPlan(data.plan as Plan);
    } else {
      setPlan("none");
    }
    setPlanStatus(data?.status ?? null);
    setSlackWebhookUrl(data?.slack_webhook_url ?? "");
  }, []);

  const loadScans = useCallback(async () => {
    const { data, error: fetchError } = await supabase
      .from("scans")
      .select("id, target_url, status, created_at")
      .order("created_at", { ascending: false });
    if (fetchError) setError(fetchError.message);
    else setScans((data ?? []) as Scan[]);
  }, []);

  useEffect(() => {
    (async () => {
      const session = await getSession();
      if (!session) {
        setAuthed(false);
        setLoading(false);
        return;
      }
      const { currentLevel, nextLevel } = await getMfaAssuranceLevel();
      if (nextLevel && currentLevel !== nextLevel) {
        router.replace("/login/mfa-challenge");
        return;
      }
      setAuthed(true);
      await Promise.all([loadScans(), loadPlan()]);
      setLoading(false);
    })().catch((err) => {
      console.error("[dashboard] init error:", (err as Error).message);
      setLoading(false);
    });
  }, [router, loadScans, loadPlan]);

  async function startScan(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setScanMessage(null);
    setError(null);

    const functionsUrl = process.env.NEXT_PUBLIC_AZURE_FUNCTIONS_URL;
    if (!functionsUrl) {
      setError("NEXT_PUBLIC_AZURE_FUNCTIONS_URL is not configured — see .env.example.");
      setSubmitting(false);
      return;
    }

    const session = await getSession();
    if (!session) {
      setError("Session expired — please sign in again.");
      setSubmitting(false);
      return;
    }

    try {
      const createRes = await fetch(`${functionsUrl}/api/run-scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.access_token}` },
        body: JSON.stringify({ targetUrl }),
      });
      const createBody = await createRes.json();
      if (!createRes.ok) throw new Error(createBody.error ?? `run-scan create failed (${createRes.status})`);

      const runRes = await fetch(`${functionsUrl}/api/run-scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session.access_token}`,
          "X-Scan-Token": createBody.proofToken,
        },
        body: JSON.stringify({ scanId: createBody.scanId }),
      });
      const runBody = await runRes.json();
      if (!runRes.ok) throw new Error(runBody.error ?? `run-scan execution failed (${runRes.status})`);

      setScanMessage(`Scan complete — score ${runBody.score}/100.`);
      setTargetUrl("");
      await loadScans();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  async function openBillingPortal() {
    setPortalLoading(true);
    try {
      const session = await getSession();
      if (!session) throw new Error("Session expired");
      const res = await fetch("/api/stripe/customer-portal", {
        method: "POST",
        headers: { Authorization: `Bearer ${session.access_token}` },
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error);
      window.location.href = body.url;
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setPortalLoading(false);
    }
  }

  async function saveSlackWebhook(e: React.FormEvent) {
    e.preventDefault();
    setSlackSaving(true);
    setSlackMessage(null);
    const { error: updateError } = await supabase
      .from("subscriptions")
      .update({ slack_webhook_url: slackWebhookUrl || null });
    setSlackSaving(false);
    setSlackMessage(updateError ? updateError.message : "Saved — alerts will post to this channel when scans complete.");
  }

  if (loading) return <div className="px-6 py-16 text-center text-sm text-slatedark/40">Loading…</div>;

  if (!authed) {
    return (
      <div className="mx-auto max-w-md px-6 py-24 text-center">
        <h1 className="text-2xl font-bold text-atlantic">Sign in required</h1>
        <Link href="/login" className="mt-6 inline-block text-atlantic underline">Sign in</Link>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl px-6 py-16 space-y-10">
      <Suspense fallback={null}>
        <CheckoutBanner />
      </Suspense>

      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-atlantic">Dashboard</h1>
        <Link href="/dashboard/scans" className="rounded-md bg-atlantic px-4 py-2 text-sm font-semibold text-white hover:opacity-90">
          All scans
        </Link>
      </div>

      {/* Subscription status */}
      {plan !== "none" && (
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-medium text-slatedark/50 uppercase tracking-wide">Current plan</p>
              <p className="mt-0.5 text-lg font-bold text-atlantic">{PLAN_LABELS[plan] ?? plan}</p>
              {planStatus === "past_due" && (
                <p className="mt-1 text-xs text-red-600">Payment failed — update your card to avoid losing access.</p>
              )}
            </div>
            <button
              onClick={openBillingPortal}
              disabled={portalLoading}
              className="rounded-lg border border-slate-200 px-4 py-2 text-sm font-medium hover:border-atlantic hover:text-atlantic disabled:opacity-50"
            >
              {portalLoading ? "Opening…" : "Manage billing"}
            </button>
          </div>
        </div>
      )}

      {planStatus === "past_due" && plan === "none" && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          Your last payment failed.{" "}
          <button onClick={openBillingPortal} className="underline">Update billing</button>{" "}
          to restore your plan.
        </div>
      )}

      <PlanUpsell plan={plan} />

      {plan === "agency" && <MonitoredTargets />}

      <DomainVerification />

      {/* Run a scan */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="mb-3 text-sm font-semibold text-slatedark/70">Run a scan</h2>
        <form onSubmit={startScan} className="flex gap-2">
          <input
            type="url"
            required
            placeholder="https://your-site.com"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="flex-1 rounded-md border border-slate-200 px-3 py-2 text-sm focus:border-atlantic focus:outline-none"
          />
          <button
            type="submit"
            disabled={submitting}
            className="rounded-md bg-seafoam px-4 py-2 text-sm font-semibold text-slatedark hover:opacity-90 disabled:opacity-50"
          >
            {submitting ? "Scanning…" : "Run scan"}
          </button>
        </form>
        <p className="mt-2 text-xs text-slatedark/40">
          Only scan sites you own or are authorised to test.
        </p>
        {scanMessage && <p className="mt-2 text-sm text-emerald-700">{scanMessage}</p>}
        {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
      </div>

      {/* Scan history */}
      <ScanList scans={scans} />

      {/* Slack alerts — Pro/Agency only */}
      {(plan === "pro" || plan === "agency") && (
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h2 className="mb-1 text-sm font-semibold text-slatedark">Slack alerts</h2>
          <p className="mb-3 text-xs text-slatedark/60">
            Post scan results to a Slack channel. Paste your{" "}
            <a href="https://api.slack.com/messaging/webhooks" target="_blank" rel="noreferrer" className="underline">
              incoming webhook URL
            </a>{" "}
            below.
          </p>
          <form onSubmit={saveSlackWebhook} className="flex gap-2">
            <input
              type="url"
              placeholder="https://hooks.slack.com/services/…"
              value={slackWebhookUrl}
              onChange={(e) => setSlackWebhookUrl(e.target.value)}
              className="flex-1 rounded-md border border-slate-200 px-3 py-2 font-mono text-xs focus:border-atlantic focus:outline-none"
            />
            <button
              type="submit"
              disabled={slackSaving}
              className="rounded-md border border-slate-200 px-4 py-2 text-sm hover:border-atlantic disabled:opacity-50"
            >
              {slackSaving ? "Saving…" : "Save"}
            </button>
          </form>
          {slackMessage && <p className="mt-2 text-xs text-emerald-700">{slackMessage}</p>}
        </div>
      )}
    </div>
  );
}

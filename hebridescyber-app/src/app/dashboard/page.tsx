"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabaseClient";
import { getSession, getMfaAssuranceLevel } from "@/lib/auth";
import ScanList, { Scan } from "@/components/ScanList";
import PlanUpsell, { Plan } from "@/components/PlanUpsell";
import DomainVerification from "@/components/DomainVerification";
import MonitoredTargets from "@/components/MonitoredTargets";

// Protected dashboard route. In App Router, real route protection should
// also happen server-side (e.g. via a proxy checking the Supabase auth
// cookie) — this client-side check is enough for local dev but is NOT
// sufficient on its own in production.
// TODO: add proxy.ts (Next.js 16+ renamed middleware.ts to proxy.ts — see
// https://nextjs.org/docs/app/guides/upgrading/version-16) to redirect
// unauthenticated requests before the page even renders.
export default function DashboardPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [authed, setAuthed] = useState(false);
  const [scans, setScans] = useState<Scan[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [plan, setPlan] = useState<Plan>("none");
  const [planStatus, setPlanStatus] = useState<string | null>(null);

  const [targetUrl, setTargetUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);

  async function loadPlan() {
    const { data } = await supabase.from("subscriptions").select("plan, status").maybeSingle();
    if (data && data.status === "active") {
      setPlan(data.plan as Plan);
    } else {
      setPlan("none");
    }
    setPlanStatus(data?.status ?? null);
  }

  async function loadScans() {
    const { data, error: fetchError } = await supabase
      .from("scans")
      .select("id, target_url, status, created_at")
      .order("created_at", { ascending: false });

    if (fetchError) {
      setError(fetchError.message);
    } else {
      setScans((data ?? []) as Scan[]);
    }
  }

  useEffect(() => {
    (async () => {
      const session = await getSession();
      if (!session) {
        setAuthed(false);
        setLoading(false);
        return;
      }

      // If this account has MFA enrolled but this session hasn't completed
      // the challenge yet (currentLevel < nextLevel), send them to
      // complete it before showing any account data.
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
  }, [router]);

  /**
   * Calls the run-scan Azure Function twice: once to create the scan and
   * receive a proof token, once more (immediately) with that token to
   * actually run it. This is only appropriate for self-service scans of
   * an account you already control — see the TODO in
   * src/functions/run-scan/index.ts about replacing the token echo with a
   * real DNS TXT / file-upload check before this flow means anything
   * security-wise.
   */
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
      // Step 1: create the scan.
      const createRes = await fetch(`${functionsUrl}/api/run-scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session.access_token}`,
        },
        body: JSON.stringify({ targetUrl }),
      });
      const createBody = await createRes.json();
      if (!createRes.ok) {
        throw new Error(createBody.error ?? `run-scan create failed (${createRes.status})`);
      }

      // Step 2: run it, proving ownership with the token from step 1.
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
      if (!runRes.ok) {
        throw new Error(runBody.error ?? `run-scan execution failed (${runRes.status})`);
      }

      setScanMessage(`Scan complete — score ${runBody.score}/100.`);
      setTargetUrl("");
      await loadScans();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return <div className="px-6 py-16 text-center">Loading…</div>;
  }

  if (!authed) {
    return (
      <div className="mx-auto max-w-md px-6 py-24 text-center">
        <h1 className="text-2xl font-bold text-atlantic">Sign in required</h1>
        <p className="mt-4 text-slatedark/80">
          You need to be signed in to view your dashboard.
        </p>
        <Link href="/login" className="mt-6 inline-block text-atlantic underline">
          Sign in
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl px-6 py-16">
      <div className="mb-8 flex items-center justify-between">
        <h1 className="text-3xl font-bold text-atlantic">Your Scans</h1>
        <Link
          href="/dashboard/scans"
          className="rounded-md bg-atlantic px-4 py-2 text-sm font-semibold text-white hover:opacity-90"
        >
          All scans
        </Link>
      </div>

      {planStatus === "past_due" && (
        <div className="mb-6 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          Your last payment failed — <Link href="/pricing" className="underline">update billing</Link> to keep your plan active.
        </div>
      )}
      <PlanUpsell plan={plan} />

      {plan === "agency" && <MonitoredTargets />}

      <DomainVerification />

      <form onSubmit={startScan} className="mb-10 flex gap-2 rounded-lg border border-slate-200 p-4">
        <input
          type="url"
          required
          placeholder="https://your-site.com"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          className="flex-1 rounded-md border border-slate-300 px-3 py-2 text-sm"
        />
        <button
          type="submit"
          disabled={submitting}
          className="rounded-md bg-seafoam px-4 py-2 text-sm font-semibold text-slatedark hover:opacity-90 disabled:opacity-50"
        >
          {submitting ? "Scanning…" : "Run scan"}
        </button>
      </form>
      {/* TODO: only scan targets you own — this form has no ownership UI yet
          beyond the token round-trip in startScan(). Add a visible
          "I confirm I own or am authorised to scan this site" checkbox
          before this goes anywhere near production. */}

      {scanMessage && <p className="mb-4 text-sm text-green-700">{scanMessage}</p>}
      {error && <p className="mb-4 text-sm text-red-600">{error}</p>}
      <ScanList scans={scans} />
    </div>
  );
}

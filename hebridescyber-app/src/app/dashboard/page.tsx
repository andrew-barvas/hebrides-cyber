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
import OnboardingChecklist from "@/components/OnboardingChecklist";
import FleetOverview from "@/components/FleetOverview";
import ScheduledReportsConfig from "@/components/ScheduledReportsConfig";
import CloudCredentialsConfig from "@/components/CloudCredentialsConfig";
import NotificationPrefsSection from "@/components/NotificationPrefsSection";
import PartnerPortalPanel from "@/components/PartnerPortalPanel";
import { FindingCard, buildFindingsView, type ViewFinding, type FindingsFilter } from "@/components/ScanReportView";
import { WafIndicator, CmsStatusPanel, TechStackPanel, SeverityBreakdown, OsintSummaryPanel } from "@/components/DashboardPanels";
import ScoreTrend, { type ScorePoint } from "@/components/ScoreTrend";
import ComplianceTrend from "@/components/ComplianceTrend";
import { diffFindings, type FindingsDiff } from "@/lib/findingsDiff";
import { findPreviousFindingsClient, findScoreHistoryClient, findComplianceHistoryClient, type CompliancePoint } from "@/lib/clientScanHistory";

const OVERVIEW_FINDINGS_PREVIEW = 5;

const PLAN_LABELS: Record<string, string> = {
  basic: "Basic — £20/mo",
  pro: "Pro — £35/mo",
  agency: "Agency — £75/mo",
};

function CheckoutBanner() {
  const searchParams = useSearchParams();
  const result = searchParams?.get("checkout") ?? null;
  if (!result) return null;
  if (result === "success") {
    return (
      <div className="rounded-lg border border-neon/30 bg-neon/10 p-4 text-sm text-neon">
        <strong>Subscription activated!</strong> Your first automated scan will run within 24 hours. Welcome aboard.
      </div>
    );
  }
  if (result === "cancelled") {
    return (
      <div className="rounded-lg border border-amber-400/30 bg-amber-400/10 p-4 text-sm text-amber-400">
        Checkout cancelled — your plan hasn&apos;t changed.{" "}
        <Link href="/pricing" className="underline text-neon">View plans</Link>
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
  const [teamsWebhookUrl, setTeamsWebhookUrl] = useState("");
  const [teamsSaving, setTeamsSaving] = useState(false);
  const [teamsMessage, setTeamsMessage] = useState<string | null>(null);
  const [portalLoading, setPortalLoading] = useState(false);

  const [targetUrl, setTargetUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);

  // E-16 (docs/ENHANCEMENTS.md): onboarding-checklist state not already
  // covered by scans/loadPlan above — hasScanned/hasReport are derived
  // from scans/overviewScan directly, and the Slack/Teams half of "has an
  // alert channel" comes from loadPlan's existing slackWebhookUrl/
  // teamsWebhookUrl state, so only the domain-verification and outbound-
  // webhook checks need a new fetch.
  const [hasVerifiedDomain, setHasVerifiedDomain] = useState(false);
  const [hasOutboundWebhook, setHasOutboundWebhook] = useState(false);

  // Security Overview — summarises the most recently completed scan
  // (whichever target that was), not an aggregate across every monitored
  // target. Matches the roadmap's single-score sketch; a multi-target
  // selector is a bigger, separate design question if that's ever needed.
  const [overviewScan, setOverviewScan] = useState<{ id: string; target_url: string; score: number; created_at: string } | null>(null);
  const [overviewFindings, setOverviewFindings] = useState<ViewFinding[]>([]);
  const [overviewDiff, setOverviewDiff] = useState<FindingsDiff | null>(null);
  const [overviewScoreHistory, setOverviewScoreHistory] = useState<ScorePoint[]>([]);
  const [overviewComplianceHistory, setOverviewComplianceHistory] = useState<CompliancePoint[]>([]);
  const [overviewFilter, setOverviewFilter] = useState<FindingsFilter>("all");
  const [overviewResults, setOverviewResults] = useState<Record<string, unknown> | null>(null);

  const loadPlan = useCallback(async () => {
    const { data } = await supabase
      .from("subscriptions")
      .select("plan, status, slack_webhook_url, ms_teams_webhook_url")
      .maybeSingle();
    if (data?.status === "active") {
      setPlan(data.plan as Plan);
    } else {
      setPlan("none");
    }
    setPlanStatus(data?.status ?? null);
    setSlackWebhookUrl(data?.slack_webhook_url ?? "");
    setTeamsWebhookUrl(data?.ms_teams_webhook_url ?? "");
  }, []);

  const loadScans = useCallback(async (currentUserId: string) => {
    const { data, error: fetchError } = await supabase
      .from("scans")
      .select("id, target_url, status, created_at, owner, scan_results(score)")
      .order("created_at", { ascending: false });
    if (fetchError) {
      setError(fetchError.message);
      return;
    }

    const rows = (data ?? []) as Array<{
      id: string; target_url: string; status: Scan["status"]; created_at: string;
      owner: string; scan_results: { score?: number | null }[] | null;
    }>;

    // Team membership (see Account -> Team) can make this list include scans
    // owned by someone else — look up their email so the row can say whose
    // it is, rather than the ambiguous mix reading like it's all the
    // viewer's own scans.
    const otherOwnerIds = [...new Set(rows.filter((r) => r.owner !== currentUserId).map((r) => r.owner))];
    const emailByOwner = new Map<string, string>();
    if (otherOwnerIds.length > 0) {
      const { data: profiles } = await supabase.from("users").select("id, email").in("id", otherOwnerIds);
      for (const p of profiles ?? []) emailByOwner.set(p.id, p.email);
    }

    setScans(
      rows.map((s) => ({
        id: s.id,
        target_url: s.target_url,
        status: s.status,
        created_at: s.created_at,
        score: s.scan_results?.[0]?.score ?? null,
        sharedByEmail: s.owner !== currentUserId ? emailByOwner.get(s.owner) ?? null : null,
      })) as Scan[]
    );
  }, []);

  const loadOverview = useCallback(async () => {
    const { data: latest } = await supabase
      .from("scans")
      .select("id, target_url, created_at, scan_results(results, score, created_at)")
      .eq("status", "completed")
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    const resultRow = (latest as { scan_results?: { results?: { findings?: ViewFinding[] }; score: number | null; created_at: string }[] } | null)
      ?.scan_results?.[0];

    if (!latest || !resultRow) {
      setOverviewScan(null);
      return;
    }

    const createdAt = resultRow.created_at ?? latest.created_at;
    const findings = resultRow.results?.findings ?? [];
    setOverviewScan({ id: latest.id, target_url: latest.target_url, score: resultRow.score ?? 0, created_at: createdAt });
    setOverviewFindings(findings);
    setOverviewResults(resultRow.results as Record<string, unknown> | null);

    const [previousFindings, history, complianceHistory] = await Promise.all([
      findPreviousFindingsClient(latest.id, latest.target_url, createdAt),
      findScoreHistoryClient(latest.id, latest.target_url, resultRow.score, createdAt),
      findComplianceHistoryClient(latest.id, latest.target_url, findings, createdAt),
    ]);

    setOverviewDiff(previousFindings ? diffFindings(findings, previousFindings) : null);
    setOverviewScoreHistory(history);
    setOverviewComplianceHistory(complianceHistory);
  }, []);

  // E-16 (docs/ENHANCEMENTS.md): both queries are existence checks only —
  // .limit(1) rather than fetching every row, since the checklist only
  // needs a boolean, not a count or the rows themselves.
  const loadOnboardingExtras = useCallback(async () => {
    const [{ data: verified }, { data: webhook }] = await Promise.all([
      supabase.from("verifications").select("id").not("verified_at", "is", null).limit(1),
      supabase.from("webhooks").select("id").limit(1),
    ]);
    setHasVerifiedDomain((verified?.length ?? 0) > 0);
    setHasOutboundWebhook((webhook?.length ?? 0) > 0);
  }, []);

  useEffect(() => {
    (async () => {
      const session = await getSession();
      if (!session) { setAuthed(false); setLoading(false); return; }
      const { currentLevel, nextLevel } = await getMfaAssuranceLevel();
      if (nextLevel && currentLevel !== nextLevel) { router.replace("/login/mfa-challenge"); return; }
      setAuthed(true);
      await Promise.all([loadScans(session.user.id), loadPlan(), loadOverview(), loadOnboardingExtras()]);
      setLoading(false);
    })().catch((err) => {
      console.error("[dashboard] init error:", (err as Error).message);
      setLoading(false);
    });
  }, [router, loadScans, loadPlan, loadOverview, loadOnboardingExtras]);

  async function deleteScan(scanId: string) {
    // scan_results.scan_id has `on delete cascade` (001_init.sql), so
    // deleting the scans row alone also removes its scan_results row — no
    // separate manual delete needed.
    const { error } = await supabase.from("scans").delete().eq("id", scanId);
    if (error) throw new Error(error.message);
    setScans((prev) => prev.filter((s) => s.id !== scanId));
  }

  async function startScan(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setScanMessage(null);
    setError(null);

    const session = await getSession();
    if (!session) { setError("Session expired — please sign in again."); setSubmitting(false); return; }

    try {
      const createRes = await fetch("/api/run-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.access_token}` },
        body: JSON.stringify({ targetUrl }),
      });
      const createBody = await createRes.json();
      if (!createRes.ok) throw new Error(createBody.error ?? `run-scan create failed (${createRes.status})`);

      // Step 2 now queues the scan rather than running it inline — see
      // src/pages/api/run-scan.ts and .github/workflows/on-demand-scan.yml
      // for why. "queued"/"running" responses mean poll again; only the
      // first call needs X-Scan-Token, since later polls hit the
      // already-"running" branch which skips ownership re-verification.
      const POLL_INTERVAL_MS = 4_000;
      const MAX_POLLS = 45; // ~3 minutes — comfortably above the on-demand workflow's expected runtime

      async function pollRunScan(withToken: boolean) {
        const res = await fetch("/api/run-scan", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${session!.access_token}`,
            ...(withToken ? { "X-Scan-Token": createBody.proofToken } : {}),
          },
          body: JSON.stringify({ scanId: createBody.scanId }),
        });
        const body = await res.json();
        if (!res.ok) throw new Error(body.error ?? `run-scan failed (${res.status})`);
        return body;
      }

      let runBody = await pollRunScan(true);
      let polls = 0;
      while ((runBody.status === "queued" || runBody.status === "running") && polls < MAX_POLLS) {
        const progress = runBody.progress as { phase?: string; checks_completed?: string[]; checks_total?: number; current_check?: string; elapsed_ms?: number } | null;
        let phase: string;
        if (runBody.status === "queued") {
          phase = "Scan queued — waiting for a runner to pick it up…";
        } else if (progress?.current_check) {
          const pct = progress.checks_total ? Math.round(((progress.checks_completed?.length ?? 0) / progress.checks_total) * 100) : 0;
          const elapsed = progress.elapsed_ms ? `${Math.round(progress.elapsed_ms / 1000)}s` : "";
          phase = `Scanning (${pct}%)${elapsed ? ` · ${elapsed}` : ""} — ${progress.current_check}`;
        } else if (polls < 8) {
          phase = "Scanning — checking TLS, headers, DNS…";
        } else if (polls < 20) {
          phase = "Scanning — probing endpoints, detecting technologies…";
        } else {
          phase = "Scanning — running deep checks, almost done…";
        }
        setScanMessage(phase);
        await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
        runBody = await pollRunScan(false);
        polls++;
      }

      if (runBody.status === "queued" || runBody.status === "running") {
        setScanMessage(
          runBody.status === "queued"
            ? "Scan is queued and will be picked up shortly. Check back in a few minutes — the page will update automatically."
            : "Scan is still running — this can take a few minutes for larger sites. Check back shortly."
        );
      } else if (runBody.status === "failed" || runBody.ok === false) {
        throw new Error(runBody.error ?? "Scan failed — try again.");
      } else {
        setScanMessage(`Scan complete — score ${runBody.score}/100.`);
        setTargetUrl("");
      }
      await Promise.all([loadScans(session.user.id), loadOverview()]);
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

  async function saveTeamsWebhook(e: React.FormEvent) {
    e.preventDefault();
    setTeamsSaving(true);
    setTeamsMessage(null);
    const { error: updateError } = await supabase
      .from("subscriptions")
      .update({ ms_teams_webhook_url: teamsWebhookUrl || null });
    setTeamsSaving(false);
    setTeamsMessage(updateError ? updateError.message : "Saved — alerts will post to this channel when scans complete.");
  }

  if (loading) {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center">
        <p className="font-mono text-sm text-cybertext/30">// loading…</p>
      </div>
    );
  }

  if (!authed) {
    return (
      <div className="bg-cyberbg min-h-screen flex flex-col items-center justify-center px-6 text-center">
        <p className="mb-3 font-mono text-sm text-neon">// auth required</p>
        <h1 className="text-2xl font-bold text-cybertext">Sign in required</h1>
        <Link href="/login" className="mt-6 inline-block text-neon underline">Sign in →</Link>
      </div>
    );
  }

  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      <div className="bg-grid pointer-events-none fixed inset-0 opacity-20" />

      <div className="relative mx-auto max-w-4xl px-4 py-10 sm:px-6 space-y-8">
        <Suspense fallback={null}>
          <CheckoutBanner />
        </Suspense>

        {/* Header */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="font-mono text-xs text-neon/50" aria-hidden="true">$ ./dashboard</p>
            <h1 className="text-2xl font-bold text-cybertext sm:text-3xl">Dashboard</h1>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link
              href="/dashboard/assets"
              className="rounded-md border border-cyberborder px-4 py-2 text-sm font-medium text-cybertext/70 hover:border-neon hover:text-neon transition-colors"
            >
              Assets →
            </Link>
            <Link
              href="/dashboard/scans"
              className="rounded-md border border-cyberborder px-4 py-2 text-sm font-medium text-cybertext/70 hover:border-neon hover:text-neon transition-colors"
            >
              All scans →
            </Link>
            <Link
              href="/dashboard/scans/history"
              className="rounded-md border border-cyberborder px-4 py-2 text-sm font-medium text-cybertext/70 hover:border-neon hover:text-neon transition-colors"
            >
              Score history →
            </Link>
          </div>
        </div>

        <FleetOverview />

        {/* Partner portal — Agency tier only */}
        {plan === "agency" && <PartnerPortalPanel />}

        {/* Scheduled report delivery — any paid plan */}
        {plan !== "none" && <ScheduledReportsConfig />}
        {plan === "agency" && <CloudCredentialsConfig />}

        {/* Security overview — most recently completed scan */}
        {overviewScan && (
          <div className="space-y-4">
            <h2 className="font-mono text-xs text-cybertext/40 uppercase tracking-wide">// security overview</h2>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5 text-center">
                <p className="text-3xl font-bold text-neon">{overviewScan.score}</p>
                <p className="mt-0.5 text-xs text-cybertext/40">/100</p>
              </div>
              <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5 text-center">
                {overviewScoreHistory.length >= 2 ? (
                  (() => {
                    const delta =
                      overviewScoreHistory[overviewScoreHistory.length - 1].score -
                      overviewScoreHistory[overviewScoreHistory.length - 2].score;
                    return (
                      <>
                        <p className={`text-3xl font-bold ${delta > 0 ? "text-neon" : delta < 0 ? "text-red-400" : "text-cybertext/50"}`}>
                          {delta > 0 ? "▲" : delta < 0 ? "▼" : "–"} {Math.abs(delta)}
                        </p>
                        <p className="mt-0.5 text-xs text-cybertext/40">vs last scan</p>
                      </>
                    );
                  })()
                ) : (
                  <>
                    <p className="text-3xl font-bold text-cybertext/30">–</p>
                    <p className="mt-0.5 text-xs text-cybertext/40">no previous scan yet</p>
                  </>
                )}
              </div>
              <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5 text-center">
                <p className="text-3xl font-bold text-cybertext">{overviewDiff ? overviewDiff.added.length : 0}</p>
                <p className="mt-0.5 text-xs text-cybertext/40">new since last scan</p>
              </div>
            </div>

            {overviewResults && (
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                <WafIndicator results={overviewResults as Parameters<typeof WafIndicator>[0]["results"]} />
                <CmsStatusPanel results={overviewResults as Parameters<typeof CmsStatusPanel>[0]["results"]} />
                <TechStackPanel results={overviewResults as Parameters<typeof TechStackPanel>[0]["results"]} />
                <OsintSummaryPanel results={overviewResults as Parameters<typeof OsintSummaryPanel>[0]["results"]} />
              </div>
            )}

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <SeverityBreakdown findings={overviewFindings} />
              {overviewScoreHistory.length >= 2 && (
                <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
                  <ScoreTrend points={overviewScoreHistory} />
                </div>
              )}
            </div>

            <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
              <ComplianceTrend findings={overviewFindings} history={overviewComplianceHistory} />
            </div>

            <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <h3 className="min-w-0 truncate font-mono text-xs text-cybertext/40 uppercase tracking-wide">
                  Findings —{" "}
                  <Link href={`/dashboard/scans/${overviewScan.id}`} className="text-neon hover:underline">
                    {overviewScan.target_url}
                  </Link>
                </h3>
                <div className="flex flex-wrap gap-1.5">
                  {(
                    [
                      ["all", `All (${overviewFindings.length})`],
                      ["new", `New (${overviewDiff?.added.length ?? 0})`],
                      ["fixed", `Fixed (${overviewDiff?.fixed.length ?? 0})`],
                    ] as const
                  ).map(([key, label]) => (
                    <button
                      key={key}
                      onClick={() => setOverviewFilter(key)}
                      className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
                        overviewFilter === key
                          ? "border-neon text-neon bg-neon/10"
                          : "border-cyberborder text-cybertext/50 hover:border-cybertext/30 hover:text-cybertext/70"
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              {(() => {
                const visible = buildFindingsView(overviewFindings, overviewDiff, overviewFilter);
                if (visible.length === 0) {
                  return (
                    <p className="text-sm text-cybertext/40">
                      {overviewFilter === "new"
                        ? "No new findings since your last scan of this target."
                        : overviewFilter === "fixed"
                          ? "No findings were fixed since your last scan of this target."
                          : "No findings on the most recent scan."}
                    </p>
                  );
                }
                return (
                  <div className="space-y-3">
                    {visible.slice(0, OVERVIEW_FINDINGS_PREVIEW).map((f, i) => (
                      <FindingCard key={f.checkId ?? i} finding={f} />
                    ))}
                    {visible.length > OVERVIEW_FINDINGS_PREVIEW && (
                      <Link
                        href={`/dashboard/scans/${overviewScan.id}`}
                        className="inline-block text-xs font-medium text-neon hover:underline"
                      >
                        View all {visible.length} in the full report →
                      </Link>
                    )}
                  </div>
                );
              })()}
            </div>
          </div>
        )}

        {/* Subscription status */}
        {plan !== "none" && (
          <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="font-mono text-xs text-cybertext/40 uppercase tracking-wide">Current plan</p>
                <p className="mt-0.5 text-lg font-bold text-neon">{PLAN_LABELS[plan] ?? plan}</p>
                {planStatus === "past_due" && (
                  <p className="mt-1 text-xs text-red-400">Payment failed — update your card to avoid losing access.</p>
                )}
              </div>
              <button
                onClick={openBillingPortal}
                disabled={portalLoading}
                className="rounded-lg border border-cyberborder px-4 py-2 text-sm font-medium text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-50 transition-colors"
              >
                {portalLoading ? "Opening…" : "Manage billing"}
              </button>
            </div>
          </div>
        )}

        {planStatus === "past_due" && plan === "none" && (
          <div className="rounded-lg border border-red-400/30 bg-red-400/10 p-4 text-sm text-red-400">
            Your last payment failed.{" "}
            <button onClick={openBillingPortal} className="underline hover:text-red-300">Update billing</button>{" "}
            to restore your plan.
          </div>
        )}

        <PlanUpsell plan={plan} />

        <OnboardingChecklist
          verifiedDomain={hasVerifiedDomain}
          hasScanned={scans.length > 0}
          hasReport={overviewScan !== null}
          hasAlertChannel={hasOutboundWebhook || Boolean(slackWebhookUrl) || Boolean(teamsWebhookUrl)}
          alertChannelIsSlackTeams={plan === "pro" || plan === "agency"}
        />

        {/* Basic/Pro/Agency all get scheduled monitoring (E-01, docs/ENHANCEMENTS.md)
            — cadence and per-plan target cap are enforced server-side
            (scanCadence.ts, sql/migrations/018_monitored_targets_plan_cap.sql),
            this is just the UI gate matching that. */}
        {plan !== "none" && <MonitoredTargets />}

        <div id="domain-verification">
          <DomainVerification />
        </div>

        {/* Run a scan */}
        <div id="run-a-scan" className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
          <h2 className="mb-3 font-mono text-xs text-cybertext/40 uppercase tracking-wide">// run a scan</h2>
          <form onSubmit={startScan} className="flex flex-col gap-2 sm:flex-row">
            <input
              type="url"
              required
              placeholder="https://your-site.com"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
            />
            <button
              type="submit"
              disabled={submitting}
              className="rounded-md bg-neon px-5 py-2.5 text-sm font-semibold text-cyberbg hover:opacity-90 disabled:opacity-50 shadow-glowsm transition-opacity"
            >
              {submitting ? "Scanning…" : "Run scan"}
            </button>
          </form>
          <p className="mt-2 text-xs text-cybertext/40">
            We scan only domains you&apos;ve verified you own. Results are
            private to your account and never shared or sold — see our{" "}
            <Link href="/privacy" className="text-neon hover:underline">
              privacy policy
            </Link>
            .
          </p>
          {scanMessage && <p className="mt-2 text-sm text-neon">{scanMessage}</p>}
          {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
        </div>

        {/* Scan history */}
        <div id="scan-history">
          <ScanList scans={scans} onDelete={deleteScan} />
        </div>

        {/* Slack alerts — Pro/Agency only */}
        {(plan === "pro" || plan === "agency") && (
          <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
            <h2 className="mb-1 font-mono text-xs text-cybertext/40 uppercase tracking-wide">// slack alerts</h2>
            <p className="mb-3 text-xs text-cybertext/60">
              Post scan results to a Slack channel. Paste your{" "}
              <a
                href="https://api.slack.com/messaging/webhooks"
                target="_blank"
                rel="noreferrer"
                className="text-neon underline hover:text-cybertext"
              >
                incoming webhook URL
              </a>{" "}
              below.
            </p>
            <form onSubmit={saveSlackWebhook} className="flex flex-col gap-2 sm:flex-row">
              <input
                type="url"
                placeholder="https://hooks.slack.com/services/…"
                value={slackWebhookUrl}
                onChange={(e) => setSlackWebhookUrl(e.target.value)}
                className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 font-mono text-xs text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
              />
              <button
                type="submit"
                disabled={slackSaving}
                className="rounded-md border border-cyberborder px-4 py-2.5 text-sm text-cybertext/70 hover:border-neon hover:text-neon disabled:opacity-50 transition-colors"
              >
                {slackSaving ? "Saving…" : "Save"}
              </button>
            </form>
            {slackMessage && <p className="mt-2 text-xs text-neon">{slackMessage}</p>}
          </div>
        )}

        {/* Microsoft Teams alerts — Pro/Agency only, independent of Slack */}
        {(plan === "pro" || plan === "agency") && (
          <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
            <h2 className="mb-1 font-mono text-xs text-cybertext/40 uppercase tracking-wide">// microsoft teams alerts</h2>
            <p className="mb-3 text-xs text-cybertext/60">
              Post scan results to a Teams channel. Add an{" "}
              <a
                href="https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook"
                target="_blank"
                rel="noreferrer"
                className="text-neon underline hover:text-cybertext"
              >
                incoming webhook
              </a>{" "}
              to the channel and paste its URL below. Independent of Slack — set either, both, or neither.
            </p>
            <form onSubmit={saveTeamsWebhook} className="flex flex-col gap-2 sm:flex-row">
              <input
                type="url"
                placeholder="https://outlook.office.com/webhook/…"
                value={teamsWebhookUrl}
                onChange={(e) => setTeamsWebhookUrl(e.target.value)}
                className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 font-mono text-xs text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
              />
              <button
                type="submit"
                disabled={teamsSaving}
                className="rounded-md border border-cyberborder px-4 py-2.5 text-sm text-cybertext/70 hover:border-neon hover:text-neon disabled:opacity-50 transition-colors"
              >
                {teamsSaving ? "Saving…" : "Save"}
              </button>
            </form>
            {teamsMessage && <p className="mt-2 text-xs text-neon">{teamsMessage}</p>}
          </div>
        )}

        {/* Email notification preferences — all plans */}
        {plan !== "none" && <NotificationPrefsSection />}
      </div>
    </div>
  );
}

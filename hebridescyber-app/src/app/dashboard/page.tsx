"use client";

// Overview — the executive summary of the account's security posture.
// Scanning, assets and integrations each have their own page in the app
// shell now (src/components/app-shell); this page only summarises and links
// out. It no longer loads the full scan list (it used to, unpaginated, just
// to answer "has this account scanned yet?") — that's a limit(1) check now.

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ScanSearch } from "lucide-react";
import { supabase } from "@/lib/supabaseClient";
import { useAppSession } from "@/components/app-shell/AppShell";
import PlanUpsell from "@/components/PlanUpsell";
import OnboardingChecklist from "@/components/OnboardingChecklist";
import FleetOverview from "@/components/FleetOverview";
import PartnerPortalPanel from "@/components/PartnerPortalPanel";
import EmergingThreatsPanel from "@/components/EmergingThreatsPanel";
import { useSessionToken } from "@/lib/useSessionToken";
import { FindingCard, buildFindingsView, type ViewFinding, type FindingsFilter } from "@/components/ScanReportView";
import { WafIndicator, CmsStatusPanel, TechStackPanel, SeverityBreakdown, OsintSummaryPanel } from "@/components/DashboardPanels";
import ScoreTrend, { type ScorePoint } from "@/components/ScoreTrend";
import ComplianceTrend from "@/components/ComplianceTrend";
import { diffFindings, type FindingsDiff } from "@/lib/findingsDiff";
import { canDetectFromResults } from "@/lib/findingLifecycle";
import { findPreviousFindingsClient, findScoreHistoryClient, findComplianceHistoryClient, type CompliancePoint } from "@/lib/clientScanHistory";
import { useBillingPortal } from "@/lib/useBillingPortal";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { SegmentedControl } from "@/components/ui/segmented-control";
import { Skeleton } from "@/components/ui/skeleton";
import { StatCard } from "@/components/ui/stat-card";

const OVERVIEW_FINDINGS_PREVIEW = 5;

type OverviewScan = { id: string; target_url: string; score: number; created_at: string };

// Summarises the most recently completed scan (whichever target that was),
// not an aggregate across targets — FleetOverview covers the multi-target
// view for accounts with more than one monitored site.
type Overview = {
  scan: OverviewScan;
  findings: ViewFinding[];
  results: Record<string, unknown> | null;
  diff: FindingsDiff | null;
  scoreHistory: ScorePoint[];
  complianceHistory: CompliancePoint[];
};

async function fetchOverview(): Promise<Overview | null> {
  const { data: latest } = await supabase
    .from("scans")
    .select("id, target_url, created_at, scan_results(results, score, created_at)")
    .eq("status", "completed")
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  const resultRow = (latest as { scan_results?: { results?: { findings?: ViewFinding[] }; score: number | null; created_at: string }[] } | null)
    ?.scan_results?.[0];
  if (!latest || !resultRow) return null;

  const createdAt = resultRow.created_at ?? latest.created_at;
  const findings = resultRow.results?.findings ?? [];

  const [previousFindings, scoreHistory, complianceHistory] = await Promise.all([
    findPreviousFindingsClient(latest.id, latest.target_url, createdAt),
    findScoreHistoryClient(latest.id, latest.target_url, resultRow.score, createdAt),
    findComplianceHistoryClient(latest.id, latest.target_url, findings, createdAt),
  ]);

  return {
    scan: { id: latest.id, target_url: latest.target_url, score: resultRow.score ?? 0, created_at: createdAt },
    findings,
    results: resultRow.results as Record<string, unknown> | null,
    diff: previousFindings ? diffFindings(findings, previousFindings, { canDetect: canDetectFromResults(resultRow.results as Record<string, unknown> | undefined) }) : null,
    scoreHistory,
    complianceHistory,
  };
}

// E-16 onboarding checklist inputs — existence checks only (.limit(1)),
// since the checklist needs booleans, not rows.
async function fetchOnboardingFlags() {
  const [{ data: verified }, { data: webhook }, { data: anyScan }] = await Promise.all([
    supabase.from("verifications").select("id").not("verified_at", "is", null).limit(1),
    supabase.from("webhooks").select("id").limit(1),
    supabase.from("scans").select("id").limit(1),
  ]);
  return {
    verifiedDomain: (verified?.length ?? 0) > 0,
    outboundWebhook: (webhook?.length ?? 0) > 0,
    scanned: (anyScan?.length ?? 0) > 0,
  };
}

// Same bands and words as ScanReportView's score ring, so a score reads the
// same wherever it appears.
function scoreBand(score: number): { tone: "brand" | "warning" | "danger"; label: string } {
  if (score >= 80) return { tone: "brand", label: "Good" };
  if (score >= 60) return { tone: "warning", label: "Fair" };
  if (score >= 40) return { tone: "danger", label: "Poor" };
  return { tone: "danger", label: "Critical" };
}

function hostnameOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function CheckoutBanner() {
  const result = useSearchParams()?.get("checkout") ?? null;
  if (result === "success") {
    return (
      <Alert variant="success" title="Subscription activated">
        Your first automated scan will run within 24 hours. Welcome aboard.
      </Alert>
    );
  }
  if (result === "cancelled") {
    return (
      <Alert variant="warning" title="Checkout cancelled">
        Your plan hasn&apos;t changed.{" "}
        <Link href="/pricing" className="font-medium text-neon hover:underline">
          View plans
        </Link>
      </Alert>
    );
  }
  return null;
}

export default function DashboardPage() {
  const { plan, planStatus, slackWebhookUrl, teamsWebhookUrl } = useAppSession();
  const billing = useBillingPortal();
  const sessionToken = useSessionToken();

  const [loaded, setLoaded] = useState(false);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [flags, setFlags] = useState({ verifiedDomain: false, outboundWebhook: false, scanned: false });
  const [overviewFilter, setOverviewFilter] = useState<FindingsFilter>("all");

  useEffect(() => {
    let cancelled = false;
    Promise.all([fetchOverview(), fetchOnboardingFlags()])
      .then(([o, f]) => {
        if (cancelled) return;
        setOverview(o);
        setFlags(f);
      })
      .catch((err) => console.error("[dashboard] overview load error:", (err as Error).message))
      .finally(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const overviewScan = overview?.scan ?? null;
  const overviewFindings = overview?.findings ?? [];
  const overviewDiff = overview?.diff ?? null;
  const overviewScoreHistory = overview?.scoreHistory ?? [];
  const overviewResults = overview?.results ?? null;

  const scanDate = overviewScan
    ? new Date(overviewScan.created_at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })
    : null;

  return (
    <div className="space-y-8">
      <Suspense fallback={null}>
        <CheckoutBanner />
      </Suspense>

      <PageHeader
        eyebrow="$ ./dashboard"
        title="Overview"
        description={
          overviewScan ? (
            <>
              Latest completed scan:{" "}
              <Link href={`/dashboard/scans/${overviewScan.id}`} className="text-neon hover:underline">
                {hostnameOf(overviewScan.target_url)}
              </Link>{" "}
              · {scanDate}
            </>
          ) : (
            "Your security posture at a glance."
          )
        }
        actions={
          <>
            {overviewScoreHistory.length >= 2 && (
              <Button asChild variant="secondary">
                <Link href="/dashboard/scans/history">View trends</Link>
              </Button>
            )}
            <Button asChild>
              <Link href="/dashboard/scans#run-a-scan">
                <ScanSearch aria-hidden="true" />
                Run a scan
              </Link>
            </Button>
          </>
        }
      />

      {planStatus === "past_due" && (
        <Alert variant="danger" title="Your last payment failed">
          <p>Paid features are paused until your billing details are updated.</p>
          <Button variant="secondary" size="sm" className="mt-2" onClick={billing.open} disabled={billing.loading}>
            {billing.loading ? "Opening…" : "Update billing"}
          </Button>
          {billing.error && <p className="mt-2 text-danger">{billing.error}</p>}
        </Alert>
      )}

      <OnboardingChecklist
        verifiedDomain={flags.verifiedDomain}
        hasScanned={flags.scanned}
        hasReport={overviewScan !== null}
        hasAlertChannel={flags.outboundWebhook || Boolean(slackWebhookUrl) || Boolean(teamsWebhookUrl)}
        alertChannelIsSlackTeams={plan === "pro" || plan === "agency"}
      />

      <FleetOverview />

      <EmergingThreatsPanel token={sessionToken} paidPlan={plan === "basic" || plan === "pro" || plan === "agency"} />

      {!loaded ? (
        <OverviewSkeleton />
      ) : overviewScan ? (
        <section aria-labelledby="security-overview-heading" className="space-y-4">
          <h2 id="security-overview-heading" className="sr-only">
            Security overview
          </h2>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {(() => {
              const band = scoreBand(overviewScan.score);
              return <StatCard label="Security score" value={overviewScan.score} suffix="/100" tone={band.tone} hint={band.label} />;
            })()}
            {overviewScoreHistory.length >= 2 ? (
              (() => {
                const delta =
                  overviewScoreHistory[overviewScoreHistory.length - 1].score -
                  overviewScoreHistory[overviewScoreHistory.length - 2].score;
                return (
                  <StatCard
                    label="Change"
                    tone={delta > 0 ? "brand" : delta < 0 ? "danger" : "muted"}
                    value={
                      <>
                        <span aria-hidden="true">{delta > 0 ? "▲ " : delta < 0 ? "▼ " : "– "}</span>
                        {Math.abs(delta)}
                        <span className="sr-only">{delta > 0 ? " points up" : delta < 0 ? " points down" : " points, no change"}</span>
                      </>
                    }
                    hint="vs previous scan"
                  />
                );
              })()
            ) : (
              <StatCard label="Change" value="–" tone="muted" hint="No previous scan of this site yet" />
            )}
            <StatCard
              label="New findings"
              value={overviewDiff ? overviewDiff.added.length : 0}
              tone={overviewDiff && overviewDiff.added.length > 0 ? "warning" : "default"}
              hint={overviewDiff ? "since previous scan" : "first scan of this site"}
            />
            {(() => {
              const urgent = overviewFindings.filter((f) => f.severity === "critical" || f.severity === "high").length;
              return <StatCard label="Critical & high" value={urgent} tone={urgent > 0 ? "danger" : "brand"} hint={urgent > 0 ? "fix these first" : "none open"} />;
            })()}
          </div>

          {overviewResults && (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <WafIndicator results={overviewResults as Parameters<typeof WafIndicator>[0]["results"]} />
              <CmsStatusPanel results={overviewResults as Parameters<typeof CmsStatusPanel>[0]["results"]} />
              <TechStackPanel results={overviewResults as Parameters<typeof TechStackPanel>[0]["results"]} />
              <OsintSummaryPanel results={overviewResults as Parameters<typeof OsintSummaryPanel>[0]["results"]} />
            </div>
          )}

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <SeverityBreakdown findings={overviewFindings} />
            {overviewScoreHistory.length >= 2 && (
              <Card>
                <ScoreTrend points={overviewScoreHistory} />
              </Card>
            )}
          </div>

          <Card>
            <ComplianceTrend findings={overviewFindings} history={overview?.complianceHistory ?? []} />
          </Card>

          <Card>
            <CardHeader>
              <div className="min-w-0">
                <CardTitle as="h3">latest findings</CardTitle>
                <Link
                  href={`/dashboard/scans/${overviewScan.id}`}
                  className="mt-1 block truncate text-sm text-neon hover:underline"
                >
                  {overviewScan.target_url}
                </Link>
              </div>
              <SegmentedControl
                aria-label="Filter findings"
                value={overviewFilter}
                onChange={setOverviewFilter}
                options={[
                  { value: "all", label: `All (${overviewFindings.length})` },
                  { value: "new", label: `New (${overviewDiff?.added.length ?? 0})` },
                  { value: "fixed", label: `Fixed (${overviewDiff?.fixed.length ?? 0})` },
                ]}
              />
            </CardHeader>

            {(() => {
              const visible = buildFindingsView(overviewFindings, overviewDiff, overviewFilter);
              if (visible.length === 0) {
                return (
                  <p className="text-sm text-cybermuted">
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
                    <Link href={`/dashboard/scans/${overviewScan.id}`} className="inline-block text-xs font-medium text-neon hover:underline">
                      View all {visible.length} in the full report →
                    </Link>
                  )}
                </div>
              );
            })()}
          </Card>
        </section>
      ) : (
        <EmptyState
          icon={<ScanSearch />}
          title={flags.scanned ? "Your first scan is on its way" : "No completed scans yet"}
          description={
            flags.scanned
              ? "Once a scan finishes, your score, findings and trends appear here."
              : "Verify a domain you own and run a scan — your score, findings and trends will appear here."
          }
          action={
            <Button asChild>
              <Link href={flags.scanned ? "/dashboard/scans#scan-history" : "/dashboard/scans#run-a-scan"}>
                {flags.scanned ? "View scans" : "Run your first scan"}
              </Link>
            </Button>
          }
        />
      )}

      {plan === "agency" && <PartnerPortalPanel />}

      <PlanUpsell plan={plan} />
    </div>
  );
}

function OverviewSkeleton() {
  return (
    <div className="space-y-4" aria-hidden="true">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-28 rounded-xl" />
        ))}
      </div>
      <Skeleton className="h-48 rounded-xl" />
    </div>
  );
}

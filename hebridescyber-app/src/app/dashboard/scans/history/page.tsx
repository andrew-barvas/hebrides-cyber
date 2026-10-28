"use client";

// Full score history for one target — docs/24-FEATURE-EXPANSION-SPEC.md #2.
// ScoreTrend.tsx (used elsewhere via findScoreHistoryClient) caps at 20
// points because it's rendered alongside a single scan's own report; this
// page starts from "pick a target" instead and has no such cap — see
// findFullScoreHistoryClient's own header for the (still bounded, at 500)
// reasoning.
import { useEffect, useState } from "react";
import Link from "next/link";
import { Download, TrendingUp } from "lucide-react";
import { supabase } from "@/lib/supabaseClient";
import ScoreTrend, { type ScorePoint } from "@/components/ScoreTrend";
import CategorySparklines from "@/components/CategorySparklines";
import { findFullScoreHistoryClient, findCategoryHistoryClient, type CategoryCountPoint } from "@/lib/clientScanHistory";
import { Button } from "@/components/ui/button";
import { Card, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";

type Target = { id: string; target_url: string };

function csvEscape(value: string): string {
  if (/[",\n]/.test(value)) return `"${value.replace(/"/g, '""')}"`;
  return value;
}

function downloadScoreHistoryCsv(targetUrl: string, points: ScorePoint[]) {
  const header = ["date", "score"];
  const rows = points.map((p) => [new Date(p.date).toISOString(), String(p.score)]);
  const csv = [header, ...rows].map((row) => row.map((cell) => csvEscape(String(cell))).join(",")).join("\r\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const safeHost = targetUrl.replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]/gi, "-");
  a.href = url;
  a.download = `${safeHost}-score-history.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export default function ScoreHistoryPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [loadingTargets, setLoadingTargets] = useState(true);
  const [scorePoints, setScorePoints] = useState<ScorePoint[]>([]);
  const [categoryHistory, setCategoryHistory] = useState<CategoryCountPoint[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  useEffect(() => {
    supabase
      .from("monitored_targets")
      .select("id, target_url")
      .order("created_at", { ascending: true })
      .then(({ data }) => {
        const list = (data ?? []) as Target[];
        setTargets(list);
        if (list.length > 0) setSelectedId(list[0].id);
        setLoadingTargets(false);
      });
  }, []);

  useEffect(() => {
    const target = targets.find((t) => t.id === selectedId);
    if (!target) return;
    setLoadingHistory(true);
    Promise.all([findFullScoreHistoryClient(target.target_url), findCategoryHistoryClient(target.target_url)])
      .then(([scores, categories]) => {
        setScorePoints(scores);
        setCategoryHistory(categories);
      })
      .finally(() => setLoadingHistory(false));
  }, [selectedId, targets]);

  const selectedTarget = targets.find((t) => t.id === selectedId);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="$ ./score --history"
        title="Trends"
        description="Full score history and findings by category for each monitored site."
      />

      {loadingTargets ? (
        <Skeleton className="h-64 rounded-xl" />
      ) : targets.length === 0 ? (
        <EmptyState
          icon={<TrendingUp />}
          title="No monitored sites yet"
          description="Trends are built from scheduled scans of the sites you monitor. Add one to start collecting history."
          action={
            <Button asChild>
              <Link href="/dashboard/assets">Go to Assets</Link>
            </Button>
          }
        />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <label htmlFor="target-select" className="text-sm text-cybermuted">
              Site
            </label>
            <select
              id="target-select"
              value={selectedId}
              onChange={(e) => setSelectedId(e.target.value)}
              className="h-9 rounded-md border border-cyberborder bg-cyberbg px-3 text-sm text-cybertext focus-visible:border-neon focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-neon/40"
            >
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.target_url}
                </option>
              ))}
            </select>
            {scorePoints.length > 0 && selectedTarget && (
              <Button
                variant="secondary"
                size="sm"
                className="ml-auto"
                onClick={() => downloadScoreHistoryCsv(selectedTarget.target_url, scorePoints)}
              >
                <Download aria-hidden="true" />
                Export CSV
              </Button>
            )}
          </div>

          {loadingHistory ? (
            <Skeleton className="h-64 rounded-xl" />
          ) : (
            <>
              <Card>
                <ScoreTrend points={scorePoints} />
                {scorePoints.length >= 2 && <p className="mt-2 text-xs text-cybermuted">{scorePoints.length} scans shown.</p>}
              </Card>

              <Card>
                <CardTitle className="mb-3">findings by category, over time</CardTitle>
                <CategorySparklines history={categoryHistory} />
              </Card>
            </>
          )}
        </>
      )}
    </div>
  );
}

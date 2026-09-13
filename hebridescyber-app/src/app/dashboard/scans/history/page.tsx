"use client";

// Full score history for one target — docs/24-FEATURE-EXPANSION-SPEC.md #2.
// ScoreTrend.tsx (used elsewhere via findScoreHistoryClient) caps at 20
// points because it's rendered alongside a single scan's own report; this
// page starts from "pick a target" instead and has no such cap — see
// findFullScoreHistoryClient's own header for the (still bounded, at 500)
// reasoning.
import { useEffect, useState } from "react";
import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";
import ScoreTrend, { type ScorePoint } from "@/components/ScoreTrend";
import CategorySparklines from "@/components/CategorySparklines";
import { findFullScoreHistoryClient, findCategoryHistoryClient, type CategoryCountPoint } from "@/lib/clientScanHistory";

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
    <div className="bg-cyberbg min-h-screen text-cybertext">
      <div className="bg-grid pointer-events-none fixed inset-0 opacity-20" />
      <div className="relative mx-auto max-w-4xl px-4 py-10 sm:px-6 space-y-6">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="font-mono text-xs text-neon/50" aria-hidden="true">$ ./score --history</p>
            <h1 className="text-2xl font-bold text-cybertext sm:text-3xl">Score History</h1>
          </div>
          <Link
            href="/dashboard"
            className="rounded-md border border-cyberborder px-4 py-2 text-sm font-medium text-cybertext/70 hover:border-neon hover:text-neon transition-colors"
          >
            ← Dashboard
          </Link>
        </div>

        {loadingTargets ? (
          <p className="font-mono text-sm text-cybertext/30">// loading…</p>
        ) : targets.length === 0 ? (
          <p className="text-sm text-cybertext/50">No monitored sites yet — add one from the dashboard to see its score history here.</p>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <label htmlFor="target-select" className="text-xs text-cybertext/50">
                Site:
              </label>
              <select
                id="target-select"
                value={selectedId}
                onChange={(e) => setSelectedId(e.target.value)}
                className="rounded-md border border-cyberborder bg-cyberbg px-3 py-1.5 text-sm text-cybertext focus:border-neon focus:outline-none"
              >
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.target_url}
                  </option>
                ))}
              </select>
              {scorePoints.length > 0 && selectedTarget && (
                <button
                  onClick={() => downloadScoreHistoryCsv(selectedTarget.target_url, scorePoints)}
                  className="ml-auto rounded-md border border-cyberborder px-3 py-1.5 text-xs text-cybertext/60 hover:border-neon hover:text-neon transition-colors"
                >
                  ↓ Export CSV
                </button>
              )}
            </div>

            {loadingHistory ? (
              <p className="font-mono text-sm text-cybertext/30">// loading history…</p>
            ) : (
              <>
                <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
                  <ScoreTrend points={scorePoints} />
                  {scorePoints.length >= 2 && <p className="mt-2 text-[10px] text-cybertext/30">{scorePoints.length} scans shown.</p>}
                </div>

                <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
                  <p className="mb-3 text-xs font-semibold text-cybertext/50 uppercase tracking-wide">Findings by category, over time</p>
                  <CategorySparklines history={categoryHistory} />
                </div>
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}

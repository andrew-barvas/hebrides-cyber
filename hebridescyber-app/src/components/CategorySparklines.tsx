"use client";

// Per-category open-finding-count trend, for the full score history page
// (src/app/dashboard/scans/history/page.tsx) — ComplianceTrend.tsx's
// "Open findings by category" bar list only ever shows the latest scan;
// this is the same categoryOf()/categoryLabel() taxonomy generalised across
// a target's whole history. Hand-rolled SVG, same "not worth a charting
// library for one line" reasoning as ScoreTrend.tsx.
import { categoryLabel } from "./ComplianceTrend";
import type { CategoryCountPoint } from "@/lib/clientScanHistory";

const WIDTH = 200;
const HEIGHT = 36;
const PAD = 3;

// More than this and the page turns into an unreadable wall of sparklines —
// the categories with the most total findings across the window are the
// ones worth a customer's attention anyway.
const MAX_CATEGORIES = 8;

function Sparkline({ points, max }: { points: number[]; max: number }) {
  if (points.length < 2 || max === 0) return null;
  const innerW = WIDTH - PAD * 2;
  const innerH = HEIGHT - PAD * 2;
  const xFor = (i: number) => PAD + (i / (points.length - 1)) * innerW;
  const yFor = (v: number) => PAD + innerH - (v / max) * innerH;
  const line = points.map((v, i) => `${xFor(i)},${yFor(v)}`).join(" ");

  return (
    <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="h-9 w-full" role="img" aria-label={`Trend from ${points[0]} to ${points[points.length - 1]}`}>
      <polyline points={line} fill="none" stroke="rgb(var(--c-neon))" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={xFor(points.length - 1)} cy={yFor(points[points.length - 1])} r="2" fill="rgb(var(--c-neon))" />
    </svg>
  );
}

export default function CategorySparklines({ history }: { history: CategoryCountPoint[] }) {
  if (history.length < 2) {
    return <p className="text-xs text-cybertext/40">Not enough scan history yet for category trends — run at least one more scan of this target.</p>;
  }

  const totals = new Map<string, number>();
  for (const point of history) {
    for (const [category, count] of Object.entries(point.counts)) {
      totals.set(category, (totals.get(category) ?? 0) + count);
    }
  }
  const topCategories = [...totals.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX_CATEGORIES).map(([category]) => category);

  if (topCategories.length === 0) {
    return <p className="text-xs text-cybertext/40">No open findings across this history — nothing to break down by category.</p>;
  }

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      {topCategories.map((category) => {
        const series = history.map((p) => p.counts[category] ?? 0);
        const max = Math.max(...series, 1);
        const latest = series[series.length - 1];
        const first = series[0];
        const delta = latest - first;
        return (
          <div key={category} className="rounded-lg border border-cyberborder bg-cyberbg/50 p-2.5">
            <div className="mb-1 flex items-center justify-between text-xs">
              <span className="truncate text-cybertext/70">{categoryLabel(category)}</span>
              <span className="flex shrink-0 items-center gap-1 font-mono text-cybertext/50">
                {latest}
                {delta !== 0 && <span className={delta > 0 ? "text-red-400" : "text-neon"}>{delta > 0 ? "▲" : "▼"}</span>}
              </span>
            </div>
            <Sparkline points={series} max={max} />
          </div>
        );
      })}
    </div>
  );
}

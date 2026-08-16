"use client";

export type ScorePoint = { date: string; score: number };

const WIDTH = 640;
const HEIGHT = 120;
const PAD_X = 8;
const PAD_Y = 12;

/**
 * Score-over-time line, hand-rolled SVG rather than a charting library —
 * one line, 0-100 range, no interactivity beyond the SVG <title> tooltips.
 * Not worth a dependency (and its bundle-size cost) for this.
 */
export default function ScoreTrend({ points }: { points: ScorePoint[] }) {
  if (points.length < 2) {
    return (
      <p className="text-xs text-cybertext/40">
        Not enough scan history yet for a trend — run at least one more scan of this target.
      </p>
    );
  }

  const innerW = WIDTH - PAD_X * 2;
  const innerH = HEIGHT - PAD_Y * 2;

  const xFor = (i: number) => PAD_X + (i / (points.length - 1)) * innerW;
  // Score is 0-100, always plotted on that fixed scale (not auto-scaled to
  // the visible min/max) — a flat line at 95 should still look near the top,
  // not stretched to fill the chart the way an auto-scaled axis would.
  const yFor = (score: number) => PAD_Y + innerH - (score / 100) * innerH;

  const linePoints = points.map((p, i) => `${xFor(i)},${yFor(p.score)}`).join(" ");
  const areaPoints = `${PAD_X},${PAD_Y + innerH} ${linePoints} ${xFor(points.length - 1)},${PAD_Y + innerH}`;

  const first = points[0];
  const last = points[points.length - 1];
  const delta = last.score - first.score;

  return (
    <div>
      <div className="mb-2 flex items-baseline justify-between">
        <p className="text-xs font-semibold text-cybertext/50 uppercase tracking-wide">Score trend</p>
        {delta !== 0 && (
          <p className={`text-xs font-medium ${delta > 0 ? "text-neon" : "text-red-400"}`}>
            {delta > 0 ? "▲" : "▼"} {Math.abs(delta)} since {new Date(first.date).toLocaleDateString("en-GB")}
          </p>
        )}
      </div>
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="w-full"
        role="img"
        aria-label={`Security score trend from ${first.score} to ${last.score} over ${points.length} scans`}
      >
        {/* Reference lines at 40/70 — the same thresholds ScoreGauge colours change at. */}
        <line x1={PAD_X} x2={WIDTH - PAD_X} y1={yFor(70)} y2={yFor(70)} stroke="rgb(var(--c-border))" strokeWidth="1" strokeDasharray="2 3" />
        <line x1={PAD_X} x2={WIDTH - PAD_X} y1={yFor(40)} y2={yFor(40)} stroke="rgb(var(--c-border))" strokeWidth="1" strokeDasharray="2 3" />

        <polygon points={areaPoints} fill="rgb(var(--c-neon) / 0.08)" />
        <polyline points={linePoints} fill="none" stroke="rgb(var(--c-neon))" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />

        {points.map((p, i) => (
          <circle key={p.date + i} cx={xFor(i)} cy={yFor(p.score)} r={i === points.length - 1 ? 3.5 : 2.5} fill="rgb(var(--c-neon))">
            <title>{`${new Date(p.date).toLocaleDateString("en-GB")}: ${p.score}/100`}</title>
          </circle>
        ))}
      </svg>
      <div className="mt-1 flex justify-between text-[10px] text-cybertext/40">
        <span>{new Date(first.date).toLocaleDateString("en-GB")}</span>
        <span>{new Date(last.date).toLocaleDateString("en-GB")}</span>
      </div>
    </div>
  );
}

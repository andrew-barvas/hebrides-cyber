"use client";

// "Plan your next rating" (scorePlanner.ts): tick findings to see the
// projected score, or pick a target rating and get the fewest fixes that reach
// it. Client-side only, from the findings already on the page, so it sends
// nothing and works on the public share page too. Fixed and triaged findings
// aren't offered: fixed ones no longer count, and triaged ones were a decision.
import { useMemo, useState } from "react";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { RATING_TARGETS, planCandidates, planToTarget, projectWithFixes, ratingLabel } from "@/lib/scorePlanner";
import type { ViewFinding } from "./ScanReportView";

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-sky-500",
  info: "bg-slate-500",
};

const LIST_LIMIT = 12;

function fmtPoints(points: number): string {
  const rounded = Math.round(points * 10) / 10;
  return `+${Number.isInteger(rounded) ? rounded : rounded.toFixed(1)}`;
}

export function ScorePlanner({ findings, score }: { findings: ViewFinding[]; score: number }) {
  const open = useMemo(() => findings.filter((f) => f.status !== "fixed" && !f.triage), [findings]);
  const triagedCounting = findings.some((f) => f.status !== "fixed" && f.triage && f.triage.state !== "false_positive");
  const candidates = useMemo(() => planCandidates(open), [open]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [showAll, setShowAll] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  if (candidates.length === 0) return null;

  const projected = projectWithFixes(score, candidates, selected);
  const targets = RATING_TARGETS.filter((t) => t.minScore > score);
  const shown = showAll ? candidates : candidates.slice(0, LIST_LIMIT);

  function toggle(checkId: string) {
    setNote(null);
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(checkId)) next.delete(checkId);
      else next.add(checkId);
      return next;
    });
  }

  function aimFor(minScore: number, label: string) {
    const plan = planToTarget(score, candidates, minScore);
    const ids = plan.fixes.map((f) => f.checkId);
    setSelected(new Set(ids));
    if (ids.some((id) => candidates.findIndex((c) => c.checkId === id) >= LIST_LIMIT)) setShowAll(true);
    setNote(
      plan.reachable
        ? `${plan.fixes.length} fix${plan.fixes.length === 1 ? "" : "es"} should take this site to ${label}.`
        : `Fixing every open finding gets to about ${plan.projected}, short of ${label}${triagedCounting ? ": accepted and snoozed findings still count" : ""}.`
    );
  }

  return (
    <Card className="no-print" aria-labelledby="score-planner-heading">
      <CardHeader>
        <div>
          <CardTitle id="score-planner-heading">Plan your next rating</CardTitle>
          <CardDescription className="mt-1">Tick what you&apos;ll fix to see where the score lands, or pick a rating and we&apos;ll choose the fewest fixes.</CardDescription>
        </div>
        <div className="text-right" aria-live="polite">
          <p className="text-xs text-cybermuted">
            Now {score} · {ratingLabel(score)}
          </p>
          <p className="text-lg font-semibold text-cybertext">
            {selected.size > 0 ? (
              <>
                After {selected.size} fix{selected.size === 1 ? "" : "es"}: {projected} · {ratingLabel(projected)}
              </>
            ) : (
              <span className="text-sm font-normal text-cybermuted">Nothing ticked yet</span>
            )}
          </p>
        </div>
      </CardHeader>

      {targets.length > 0 && (
        <div className="mb-3 flex flex-wrap gap-2">
          {[...targets].reverse().map((t) => (
            <Button key={t.label} variant="secondary" size="sm" onClick={() => aimFor(t.minScore, t.label)}>
              Reach {t.label} ({t.minScore}+)
            </Button>
          ))}
          {selected.size > 0 && (
            <Button variant="ghost" size="sm" onClick={() => { setSelected(new Set()); setNote(null); }}>
              Clear
            </Button>
          )}
        </div>
      )}
      {note && <p className="mb-3 text-sm text-cybertext" role="status">{note}</p>}

      <ul className="divide-y divide-cyberborder rounded-lg border border-cyberborder">
        {shown.map((c) => (
          <li key={c.checkId}>
            <label className="flex cursor-pointer items-center gap-3 px-3 py-2 text-sm hover:bg-cybertext/5">
              <input type="checkbox" className="h-4 w-4 accent-neon" checked={selected.has(c.checkId)} onChange={() => toggle(c.checkId)} />
              <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${SEVERITY_DOT[c.severity]}`} aria-hidden="true" />
              <span className="min-w-0 flex-1 truncate text-cybertext/90" title={c.title}>{c.title}</span>
              <span className="shrink-0 font-mono text-xs text-neon" aria-label={`worth about ${Math.round(c.points)} points`}>{fmtPoints(c.points)}</span>
            </label>
          </li>
        ))}
      </ul>
      {candidates.length > LIST_LIMIT && (
        <button type="button" className="mt-2 text-xs text-cybermuted underline hover:text-cybertext" onClick={() => setShowAll((v) => !v)}>
          {showAll ? "Show fewer" : `Show all ${candidates.length}`}
        </button>
      )}
      <p className="mt-3 text-xs text-cybermuted">
        An estimate from this scan&apos;s scoring. Your next scan sets the real score, and &ldquo;Check it&apos;s fixed&rdquo; on each finding confirms a fix straight away.
        {triagedCounting ? " Accepted and snoozed findings still count towards the score and aren't listed here." : ""}
      </p>
    </Card>
  );
}

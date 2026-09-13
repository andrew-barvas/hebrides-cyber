"use client";

// Fix Wizard — docs/24-FEATURE-EXPANSION-SPEC.md #15. Pure UI composition
// over data and action buttons that already exist: groups a scan's open
// findings by fixDifficulty (easiest first) with severity as a tiebreak
// (highest-impact first within the same difficulty), then walks through
// them one at a time reusing FindingCard as-is — the same remediation
// markdown, retest button, and create-ticket button a customer already
// gets on the normal findings list, just presented one at a time instead
// of all at once.
import { useState } from "react";
import { FindingCard, type ViewFinding, type Severity } from "./ScanReportView";
import type { FixDifficulty } from "@/lib/scanners/fixDifficulty";

const DIFFICULTY_RANK: Record<FixDifficulty, number> = { trivial: 0, easy: 1, moderate: 2, hard: 3 };
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Exported for testing — an unrated finding (no fixDifficulty) sorts after
// every rated one, since there's no effort estimate to place it by.
export function sortForWizard(findings: ViewFinding[]): ViewFinding[] {
  return [...findings].sort((a, b) => {
    const da = a.fixDifficulty ? DIFFICULTY_RANK[a.fixDifficulty] : 4;
    const db = b.fixDifficulty ? DIFFICULTY_RANK[b.fixDifficulty] : 4;
    if (da !== db) return da - db;
    return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  });
}

const SWIPE_THRESHOLD_PX = 50;

export default function FixWizard({
  findings,
  scanId,
  token,
  hasTicketIntegration,
  onClose,
}: {
  findings: ViewFinding[];
  scanId?: string;
  token?: string;
  hasTicketIntegration?: boolean;
  onClose: () => void;
}) {
  const open = findings.filter((f) => f.status !== "fixed");
  const ordered = sortForWizard(open);
  const [index, setIndex] = useState(0);
  const [touchStartX, setTouchStartX] = useState<number | null>(null);

  if (ordered.length === 0) {
    return (
      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-6 text-center">
        <p className="text-sm text-cybertext/60">No open findings to walk through.</p>
        <button onClick={onClose} className="mt-3 text-xs text-neon hover:underline">
          ← Back to full report
        </button>
      </div>
    );
  }

  const current = ordered[Math.min(index, ordered.length - 1)];
  const atStart = index === 0;
  const atEnd = index === ordered.length - 1;

  function next() {
    setIndex((i) => Math.min(i + 1, ordered.length - 1));
  }
  function prev() {
    setIndex((i) => Math.max(i - 1, 0));
  }

  function handleTouchStart(e: React.TouchEvent) {
    setTouchStartX(e.touches[0].clientX);
  }
  function handleTouchEnd(e: React.TouchEvent) {
    if (touchStartX === null) return;
    const delta = e.changedTouches[0].clientX - touchStartX;
    if (delta > SWIPE_THRESHOLD_PX) prev();
    else if (delta < -SWIPE_THRESHOLD_PX) next();
    setTouchStartX(null);
  }

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-cybertext">Fix wizard</p>
          <p className="text-xs text-cybertext/50">
            Step {index + 1} of {ordered.length} — ordered easiest to fix first.
          </p>
        </div>
        <button onClick={onClose} className="text-xs text-cybertext/50 hover:text-neon transition-colors">
          Exit wizard
        </button>
      </div>

      <div className="mb-4 h-1 w-full overflow-hidden rounded-full bg-cyberbg">
        <div className="h-1 rounded-full bg-neon transition-all" style={{ width: `${((index + 1) / ordered.length) * 100}%` }} />
      </div>

      <div onTouchStart={handleTouchStart} onTouchEnd={handleTouchEnd}>
        <FindingCard finding={current} scanId={scanId} token={token} hasTicketIntegration={hasTicketIntegration} />
      </div>

      <div className="mt-4 flex items-center justify-between gap-2">
        <button
          onClick={prev}
          disabled={atStart}
          className="rounded-md border border-cyberborder px-4 py-2 text-sm text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-30 transition-colors"
        >
          ← Previous
        </button>
        <button
          onClick={next}
          disabled={atEnd}
          className="rounded-md bg-neon px-4 py-2 text-sm font-semibold text-cyberbg hover:opacity-90 disabled:opacity-30 shadow-glowsm transition-opacity"
        >
          Next →
        </button>
      </div>
    </div>
  );
}

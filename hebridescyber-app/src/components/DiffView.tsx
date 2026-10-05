"use client";

// Arbitrary-pair scan comparison — docs/24-FEATURE-EXPANSION-SPEC.md #17.
// The dashboard's existing New/Fixed filter (findingsDiff.ts, used from
// src/app/dashboard/scans/[id]/page.tsx) always compares "this scan vs. the
// one immediately before it." This lets a customer pick ANY two of a
// target's past scans — diffFindings() itself already operates on any two
// Finding[] arrays, so this is purely a picker UI over it, no new diff
// logic.
import { useEffect, useState } from "react";
import { diffFindings } from "@/lib/findingsDiff";
import { findScanForDiff, type ScanListEntry } from "@/lib/clientScanHistory";
import { canDetectFromResults } from "@/lib/findingLifecycle";
import { SEVERITY_META, type ViewFinding } from "./ScanReportView";

function ScanPicker({
  label,
  scans,
  value,
  onChange,
}: {
  label: string;
  scans: ScanListEntry[];
  value: string;
  onChange: (id: string) => void;
}) {
  return (
    <div className="flex flex-1 flex-col gap-1">
      <label className="text-xs text-cybertext/50">{label}</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext focus:border-neon focus:outline-none"
      >
        {scans.map((s) => (
          <option key={s.id} value={s.id}>
            {new Date(s.createdAt).toLocaleString()} {s.score !== null ? `— ${s.score}/100` : ""}
          </option>
        ))}
      </select>
    </div>
  );
}

function FindingRow({ finding }: { finding: ViewFinding }) {
  const meta = SEVERITY_META[finding.severity];
  return (
    <div className="flex items-start gap-2 rounded-lg border border-cyberborder bg-cyberbg/50 p-2.5 text-xs">
      <span className={`shrink-0 rounded-full ${meta.bg} border ${meta.border} px-1.5 py-0.5 font-medium ${meta.text}`}>{finding.severity}</span>
      <span className="text-cybertext/70">{finding.title}</span>
    </div>
  );
}

export default function DiffView({ scans, initialScanId }: { scans: ScanListEntry[]; initialScanId: string }) {
  // Defaults: the "after" side is the scan the user arrived from; "before"
  // defaults to the next-oldest scan, the same pair the New/Fixed filter
  // would already show — the picker is there to let them pick anything
  // ELSE, not to force a different starting point.
  const initialIndex = scans.findIndex((s) => s.id === initialScanId);
  const [beforeId, setBeforeId] = useState(scans[initialIndex + 1]?.id ?? scans[scans.length - 1]?.id ?? "");
  const [afterId, setAfterId] = useState(initialScanId);
  const [beforeFindings, setBeforeFindings] = useState<ViewFinding[] | null>(null);
  const [afterFindings, setAfterFindings] = useState<ViewFinding[] | null>(null);
  const [afterResults, setAfterResults] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!beforeId || !afterId) return;
    setLoading(true);
    Promise.all([findScanForDiff(beforeId), findScanForDiff(afterId)])
      .then(([before, after]) => {
        setBeforeFindings(before?.findings ?? []);
        setAfterFindings(after?.findings ?? []);
        setAfterResults(after?.results ?? null);
      })
      .finally(() => setLoading(false));
  }, [beforeId, afterId]);

  if (scans.length < 2) {
    return <p className="text-sm text-cybertext/50">Need at least two completed scans of this target to compare.</p>;
  }

  const diff = beforeFindings && afterFindings ? diffFindings(afterFindings, beforeFindings, { canDetect: canDetectFromResults(afterResults) }) : null;

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row">
        <ScanPicker label="Before" scans={scans} value={beforeId} onChange={setBeforeId} />
        <ScanPicker label="After" scans={scans} value={afterId} onChange={setAfterId} />
      </div>

      {loading ? (
        <p className="font-mono text-sm text-cybertext/30">// comparing…</p>
      ) : beforeId === afterId ? (
        <p className="text-sm text-cybertext/50">Pick two different scans to compare.</p>
      ) : diff ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <p className="mb-2 text-xs font-semibold text-cybertext/50 uppercase tracking-wide">New ({diff.added.length})</p>
            {diff.added.length === 0 ? (
              <p className="text-xs text-cybertext/40">No new findings between these two scans.</p>
            ) : (
              <div className="space-y-2">
                {diff.added.map((f, i) => (
                  <FindingRow key={f.checkId ?? i} finding={f} />
                ))}
              </div>
            )}
          </div>
          <div>
            <p className="mb-2 text-xs font-semibold text-cybertext/50 uppercase tracking-wide">Fixed ({diff.fixed.length})</p>
            {diff.fixed.length === 0 ? (
              <p className="text-xs text-cybertext/40">No findings resolved between these two scans.</p>
            ) : (
              <div className="space-y-2">
                {diff.fixed.map((f, i) => (
                  <FindingRow key={f.checkId ?? i} finding={f} />
                ))}
              </div>
            )}
          </div>
        </div>
      ) : null}
    </div>
  );
}

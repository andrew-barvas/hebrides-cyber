"use client";

import { useState } from "react";
import type { CeReadinessReport, CeControlAssessment } from "@/lib/cyberEssentialsReadiness";

function StatusBadge({ status }: { status: CeControlAssessment["status"] }) {
  const styles = {
    pass: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    fail: "bg-red-500/20 text-red-400 border-red-500/30",
    partial: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    "not-assessed": "bg-cybertext/10 text-cybertext/50 border-cybertext/20",
  };
  const labels = { pass: "Pass", fail: "Fail", partial: "Partial", "not-assessed": "N/A" };
  return (
    <span className={`inline-block rounded border px-2 py-0.5 font-mono text-xs font-semibold ${styles[status]}`}>
      {labels[status]}
    </span>
  );
}

function ControlCard({ assessment }: { assessment: CeControlAssessment }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border border-cyberborder bg-cyberbg p-4">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between text-left"
      >
        <div className="flex items-center gap-3">
          <StatusBadge status={assessment.status} />
          <span className="font-semibold text-sm text-cybertext">{assessment.control}</span>
        </div>
        <span className="text-cybertext/40 text-xs">{open ? "Hide" : "Details"}</span>
      </button>
      {open && (
        <div className="mt-3 space-y-2 border-t border-cyberborder pt-3">
          {assessment.evidence.length > 0 && (
            <div>
              <p className="font-mono text-[10px] uppercase tracking-wider text-emerald-400/70 mb-1">Evidence</p>
              <ul className="space-y-1">
                {assessment.evidence.map((e, i) => (
                  <li key={i} className="text-xs text-cybertext/70 pl-3 border-l-2 border-emerald-500/30">{e}</li>
                ))}
              </ul>
            </div>
          )}
          {assessment.gaps.length > 0 && (
            <div>
              <p className="font-mono text-[10px] uppercase tracking-wider text-red-400/70 mb-1">Gaps</p>
              <ul className="space-y-1">
                {assessment.gaps.map((g, i) => (
                  <li key={i} className="text-xs text-cybertext/70 pl-3 border-l-2 border-red-500/30">{g}</li>
                ))}
              </ul>
            </div>
          )}
          {assessment.findings.length > 0 && (
            <p className="text-[10px] text-cybertext/40 mt-2">
              {assessment.findings.length} related finding{assessment.findings.length !== 1 ? "s" : ""} from scan
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export default function CeReadinessPanel({ report }: { report: CeReadinessReport | null }) {
  if (!report) return null;

  const statusColors = {
    ready: "text-emerald-400",
    "not-ready": "text-red-400",
    partial: "text-amber-400",
  };
  const statusLabels = {
    ready: "Ready",
    "not-ready": "Not Ready",
    partial: "Partially Ready",
  };

  return (
    <div className="rounded-lg border border-cyberborder bg-cyberpanel p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-semibold text-cybertext">Cyber Essentials Readiness</h3>
        <div className="flex items-center gap-2">
          <span className="font-mono text-2xl font-bold text-neon">{report.score}%</span>
          <span className={`font-mono text-xs font-semibold ${statusColors[report.overall_status]}`}>
            {statusLabels[report.overall_status]}
          </span>
        </div>
      </div>

      <div className="mb-4 h-2 rounded-full bg-cyberborder overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${
            report.overall_status === "ready"
              ? "bg-emerald-500"
              : report.overall_status === "partial"
                ? "bg-amber-500"
                : "bg-red-500"
          }`}
          style={{ width: `${report.score}%` }}
        />
      </div>

      <p className="text-xs text-cybertext/60 mb-4">{report.recommendation}</p>

      <div className="space-y-2">
        {report.controls.map((c) => (
          <ControlCard key={c.control} assessment={c} />
        ))}
      </div>

      <p className="mt-4 text-[10px] text-cybertext/40 leading-relaxed">
        This is an automated readiness indicator based on external scanning, not a certification.
        The formal Cyber Essentials self-assessment also covers internal controls (endpoint security, access policies, staff training)
        that require a full questionnaire at{" "}
        <a href="https://www.ncsc.gov.uk/cyberessentials/overview" target="_blank" rel="noopener noreferrer" className="text-neon/60 hover:text-neon">
          ncsc.gov.uk/cyberessentials
        </a>.
      </p>
    </div>
  );
}

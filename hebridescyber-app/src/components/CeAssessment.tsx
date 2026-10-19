"use client";

// The Cyber Essentials self-assessment assistant. Three parts stitched into one
// readiness view:
//   (a) the scan-derived evidence — the latest completed scan's findings run
//       through assessCeReadiness (the same pure function the scan report uses);
//   (b) the customer's saved answers to the human-only questions, from
//       /api/account/ce-assessment;
//   (c) combineReadiness() merging the two into a per-control status, rendered
//       alongside the questionnaire the customer edits (autosaved on change).
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { supabase } from "@/lib/supabaseClient";
import { Alert } from "@/components/ui/alert";
import { Card, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { assessCeReadiness, type CeReadinessReport } from "@/lib/cyberEssentialsReadiness";
import {
  CE_QUESTIONS,
  combineReadiness,
  type CeAnswer,
  type CeAnswerValue,
  type CombinedControl,
} from "@/lib/ceSelfAssessment";
import type { Finding } from "@/lib/scanners";

const ANSWER_OPTIONS: { value: CeAnswerValue; label: string }[] = [
  { value: "yes", label: "Yes" },
  { value: "partial", label: "Partial" },
  { value: "no", label: "No" },
  { value: "na", label: "N/A" },
];

const STATUS_STYLE: Record<CombinedControl["status"], { badge: string; label: string }> = {
  pass: { badge: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30", label: "Pass" },
  partial: { badge: "bg-amber-500/20 text-amber-400 border-amber-500/30", label: "Partial" },
  fail: { badge: "bg-red-500/20 text-red-400 border-red-500/30", label: "Fail" },
  "not-assessed": { badge: "bg-cybertext/10 text-cybermuted border-cyberborder", label: "N/A" },
};

const OVERALL_STYLE = {
  ready: { color: "text-emerald-400", bar: "bg-emerald-500", label: "Ready" },
  partial: { color: "text-amber-400", bar: "bg-amber-500", label: "Partially ready" },
  "not-ready": { color: "text-red-400", bar: "bg-red-500", label: "Not ready" },
} as const;

export default function CeAssessment({ token }: { token: string | null }) {
  const [scanReport, setScanReport] = useState<CeReadinessReport | null>(null);
  const [answers, setAnswers] = useState<Map<string, CeAnswer>>(new Map());
  const [loading, setLoading] = useState(true);
  const [available, setAvailable] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [saveState, setSaveState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const savedTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // (a) Latest completed scan's findings → scan-derived readiness. RLS scopes
  // the query to this owner; no scan yet just leaves the scan half empty.
  const loadScan = useCallback(async () => {
    const { data } = await supabase
      .from("scans")
      .select("id, created_at, scan_results(results)")
      .eq("status", "completed")
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    const results = (data as { scan_results?: { results?: { findings?: Finding[] } }[] } | null)?.scan_results?.[0]?.results;
    if (results?.findings) setScanReport(assessCeReadiness(results.findings));
  }, []);

  // (b) Saved answers from the API.
  const loadAnswers = useCallback(async () => {
    if (!token) return;
    const res = await fetch("/api/account/ce-assessment", { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error("Could not load your saved answers.");
    const body = (await res.json()) as { available: boolean; answers: CeAnswer[] };
    setAvailable(body.available);
    setAnswers(new Map(body.answers.map((a) => [a.questionKey, a])));
  }, [token]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setLoadError(null);
    Promise.all([loadScan(), loadAnswers()])
      .catch((err: Error) => {
        if (!cancelled) setLoadError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [loadScan, loadAnswers]);

  const combined = useMemo(() => combineReadiness(scanReport, [...answers.values()]), [scanReport, answers]);

  const persist = useCallback(
    async (next: Map<string, CeAnswer>) => {
      if (!token) return;
      setSaveState("saving");
      try {
        const res = await fetch("/api/account/ce-assessment", {
          method: "PUT",
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
          body: JSON.stringify({ answers: [...next.values()] }),
        });
        if (!res.ok) throw new Error("save failed");
        setSaveState("saved");
        if (savedTimer.current) clearTimeout(savedTimer.current);
        savedTimer.current = setTimeout(() => setSaveState("idle"), 2000);
      } catch {
        setSaveState("error");
      }
    },
    [token]
  );

  const onAnswer = useCallback(
    (questionKey: string, answer: CeAnswerValue) => {
      setAnswers((prev) => {
        const next = new Map(prev);
        next.set(questionKey, { ...next.get(questionKey), questionKey, answer });
        void persist(next);
        return next;
      });
    },
    [persist]
  );

  if (loading) return <Skeleton className="h-96 w-full rounded-lg" />;
  if (loadError) return <Alert variant="danger">{loadError}</Alert>;
  if (!available) {
    return (
      <EmptyState
        title="Self-assessment not enabled yet"
        description="The server needs database migration 061 applied before answers can be saved. This happens automatically on the next deploy."
      />
    );
  }

  const overall = OVERALL_STYLE[combined.overall_status];

  return (
    <div className="space-y-6">
      {/* Combined readiness summary */}
      <Card>
        <div className="flex items-center justify-between">
          <CardTitle>Combined readiness</CardTitle>
          <div className="flex items-center gap-2">
            <span className="font-mono text-2xl font-bold text-neon">{combined.score}%</span>
            <span className={`font-mono text-xs font-semibold ${overall.color}`}>{overall.label}</span>
          </div>
        </div>
        <div className="mt-3 h-2 overflow-hidden rounded-full bg-cyberborder">
          <div className={`h-full rounded-full transition-all ${overall.bar}`} style={{ width: `${combined.score}%` }} />
        </div>
        <p className="mt-3 text-xs text-cybermuted">{combined.recommendation}</p>
        <p className="mt-2 text-[11px] text-cybermuted">
          {combined.answered} of {combined.total_questions} questions answered.
          {scanReport ? " Scan evidence is from your latest completed scan." : " Run a scan to add the external-evidence half."}
        </p>
      </Card>

      {saveState === "error" && <Alert variant="danger">Couldn&apos;t save your last answer. Change it again to retry.</Alert>}

      {/* Per-control questionnaire + merged status */}
      {combined.controls.map((control) => {
        const style = STATUS_STYLE[control.status];
        return (
          <Card key={control.control}>
            <div className="flex items-center justify-between gap-3">
              <CardTitle className="text-sm">{control.control}</CardTitle>
              <span className={`inline-block rounded border px-2 py-0.5 font-mono text-xs font-semibold ${style.badge}`}>{style.label}</span>
            </div>
            {control.scanStatus && (
              <p className="mt-1 text-[11px] text-cybermuted">
                Scan evidence for this control: <span className="font-mono">{control.scanStatus}</span>
              </p>
            )}
            <ul className="mt-3 space-y-4">
              {control.questions.map((q) => (
                <li key={q.key}>
                  <p className="text-sm text-cybertext">{q.prompt}</p>
                  <p className="mt-0.5 text-[11px] text-cybermuted">{q.help}</p>
                  <div className="mt-2 flex flex-wrap gap-2" role="group" aria-label={q.prompt}>
                    {ANSWER_OPTIONS.map((opt) => {
                      const selected = q.answer === opt.value;
                      return (
                        <button
                          key={opt.value}
                          type="button"
                          aria-pressed={selected}
                          onClick={() => onAnswer(q.key, opt.value)}
                          className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                            selected ? "border-neon/50 bg-neon/10 text-neon" : "border-cyberborder text-cybermuted hover:text-cybertext"
                          }`}
                        >
                          {opt.label}
                        </button>
                      );
                    })}
                  </div>
                </li>
              ))}
            </ul>
            {control.gaps.length > 0 && (
              <div className="mt-4 border-t border-cyberborder pt-3">
                <p className="mb-1 font-mono text-[10px] uppercase tracking-wider text-red-400/70">Gaps</p>
                <ul className="space-y-1">
                  {control.gaps.map((g, i) => (
                    <li key={i} className="border-l-2 border-red-500/30 pl-3 text-xs text-cybermuted">{g}</li>
                  ))}
                </ul>
              </div>
            )}
          </Card>
        );
      })}

      <p className="text-[10px] leading-relaxed text-cybermuted">
        This combines automated external scanning with your own answers to the questions a scan can&apos;t see. It is a readiness
        aid, not a certification. Submit the formal self-assessment to your certification body at{" "}
        <a href="https://www.ncsc.gov.uk/cyberessentials/overview" target="_blank" rel="noopener noreferrer" className="text-neon/60 hover:text-neon">
          ncsc.gov.uk/cyberessentials
        </a>
        .
      </p>
    </div>
  );
}

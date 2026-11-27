"use client";

// The review screen: every drafted answer with the evidence it cites and a
// confidence level. The customer accepts, edits or rejects each one; nothing
// is final until a person accepts it. Exports the original spreadsheet with
// Answer, Evidence and Status columns.

import { useCallback, useEffect, useMemo, useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { SegmentedControl } from "@/components/ui/segmented-control";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { downloadExport, getQuestionnaire, reviewAnswers, saveBlob, wordWithAi, type QuestionnaireDetail, type ReviewAnswer } from "@/lib/questionnaire/client";
import { CONFIDENCE_LABELS, DRAFT_DISCLAIMER, NEEDS_YOUR_ANSWER, statusLabel, type AnswerStatus, type Confidence } from "@/lib/questionnaire/types";

type Filter = "all" | "needs_answer" | "draft" | "accepted" | "rejected";

const CONFIDENCE_CLASS: Record<Confidence, string> = {
  high: "border-neon/40 text-neon",
  medium: "border-cyberborder text-cybertext",
  low: "border-warning/40 text-warning",
  none: "border-danger/40 text-danger",
};

const STATUS_CLASS: Record<AnswerStatus, string> = {
  accepted: "bg-neon/10 text-neon",
  draft: "bg-cyberborder/50 text-cybertext",
  needs_answer: "bg-danger/10 text-danger",
  rejected: "bg-cyberborder/30 text-cybermuted",
};

function AnswerCard({ a, onReview, busy }: { a: ReviewAnswer; onReview: (action: "accept" | "reject" | "reset" | "edit", text?: string) => Promise<void>; busy: boolean }) {
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(a.answer);
  const needs = a.status === "needs_answer";
  const decided = a.status === "accepted" || a.status === "rejected";

  return (
    <li className="space-y-3 rounded-xl border border-cyberborder bg-cyberpanel p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <p className="min-w-0 flex-1 font-medium text-cybertext">
          <span className="mr-2 font-mono text-xs text-cybermuted">Row {a.row_index + 1}</span>
          {a.question}
        </p>
        <div className="flex shrink-0 flex-wrap gap-1.5 text-xs">
          <span className={cn("rounded px-2 py-0.5", STATUS_CLASS[a.status])}>{statusLabel(a.status, a.edited)}</span>
          <span className={cn("rounded border px-2 py-0.5", CONFIDENCE_CLASS[a.confidence])}>Confidence: {CONFIDENCE_LABELS[a.confidence]}</span>
          {a.ai_worded && <span className="rounded border border-cyberborder px-2 py-0.5 text-cybermuted">AI-worded</span>}
          {a.reused_from && <span className="rounded border border-cyberborder px-2 py-0.5 text-cybermuted">Reused</span>}
        </div>
      </div>

      {editing || (needs && !a.answer) ? (
        <div className="space-y-2">
          <Textarea aria-label={`Your answer to row ${a.row_index + 1}`} value={text} placeholder={needs ? "We hold no evidence for this. Write your answer." : undefined} onChange={(e) => setText(e.target.value)} rows={3} maxLength={4000} />
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              disabled={busy || !text.trim()}
              onClick={async () => {
                await onReview("edit", text.trim());
                setEditing(false);
              }}
            >
              Save and accept
            </Button>
            {editing && (
              <Button size="sm" variant="ghost" onClick={() => { setEditing(false); setText(a.answer); }}>
                Cancel
              </Button>
            )}
          </div>
        </div>
      ) : (
        <p className={cn("whitespace-pre-wrap text-sm", a.status === "rejected" ? "text-cybermuted line-through" : "text-cybertext")}>{a.answer || NEEDS_YOUR_ANSWER}</p>
      )}

      {a.evidence.length > 0 ? (
        <div>
          <p className="text-xs font-semibold text-cybermuted">Evidence</p>
          <ul className="mt-1 space-y-1 text-xs text-cybermuted">
            {a.evidence.map((e, i) => (
              <li key={i}>
                <span className="text-cybertext">{e.label}</span>
                {e.date ? ` (${e.date})` : ""}: {e.detail}
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="text-xs text-cybermuted">No evidence held for this question.</p>
      )}

      {!decided && !editing && (
        <div className="flex flex-wrap gap-2">
          {!needs && (
            <Button size="sm" disabled={busy} onClick={() => onReview("accept")}>
              Accept
            </Button>
          )}
          {!needs && (
            <Button size="sm" variant="secondary" disabled={busy} onClick={() => { setText(a.answer); setEditing(true); }}>
              Edit
            </Button>
          )}
          <Button size="sm" variant="ghost" disabled={busy} onClick={() => onReview("reject")}>
            Reject
          </Button>
        </div>
      )}
      {decided && (
        <div className="flex flex-wrap gap-2">
          {a.status === "accepted" && (
            <Button size="sm" variant="secondary" disabled={busy} onClick={() => { setText(a.answer); setEditing(true); }}>
              Edit
            </Button>
          )}
          <Button size="sm" variant="ghost" disabled={busy} onClick={() => onReview("reset")}>
            Undo
          </Button>
        </div>
      )}
    </li>
  );
}

export default function QuestionnaireReview({ token, id }: { token: string | null; id: string }) {
  const [data, setData] = useState<QuestionnaireDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState<Filter>("all");
  const [wording, setWording] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    try {
      setData(await getQuestionnaire(token, id));
    } catch (err) {
      setError((err as Error).message);
    }
  }, [token, id]);

  useEffect(() => {
    if (!token) return;
    let live = true;
    getQuestionnaire(token, id)
      .then((d) => live && setData(d))
      .catch((err: Error) => live && setError(err.message));
    return () => {
      live = false;
    };
  }, [token, id]);

  const shown = useMemo(() => (data ? data.answers.filter((a) => filter === "all" || a.status === filter) : []), [data, filter]);
  const highDrafts = useMemo(() => (data ? data.answers.filter((a) => a.status === "draft" && a.confidence === "high") : []), [data]);

  async function review(ids: string[], action: "accept" | "reject" | "reset" | "edit", text?: string) {
    if (!token || !ids.length) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = action === "edit" ? await reviewAnswers(token, id, { action, answerIds: [ids[0]], answer: text ?? "" }) : await reviewAnswers(token, id, { action, answerIds: ids });
      if (res.skipped.length) setNotice(`${res.skipped.length} answer${res.skipped.length === 1 ? "" : "s"} still need writing before they can be accepted.`);
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function polish() {
    if (!token) return;
    setBusy(true);
    setError(null);
    let total = 0;
    try {
      for (let i = 0; i < 100; i++) {
        setWording(`Rewording drafts… ${total} done`);
        const res = await wordWithAi(token, id);
        if (res.status !== "ok") {
          setNotice("AI wording isn't available right now. Your rule-based drafts are unchanged.");
          break;
        }
        total += res.worded;
        if (res.remaining <= 0) {
          setNotice(`AI reworded ${total} draft${total === 1 ? "" : "s"}. Check each one before accepting.`);
          break;
        }
      }
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setWording(null);
      setBusy(false);
    }
  }

  async function exportAs(format: "xlsx" | "csv") {
    if (!token) return;
    setError(null);
    try {
      const { blob, fileName } = await downloadExport(token, id, format);
      saveBlob(blob, fileName);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  if (!data) return error ? <Alert variant="danger">{error}</Alert> : <Skeleton className="h-64 w-full" />;
  const { counts } = data;
  const unreviewed = counts.draft + counts.needs_answer;

  return (
    <div className="space-y-5">
      <Alert variant="warning" title="Draft answers, not certification">
        {DRAFT_DISCLAIMER}
      </Alert>
      {error && <Alert variant="danger">{error}</Alert>}
      {notice && <Alert variant="info">{notice}</Alert>}
      {wording && <Alert variant="info">{wording}</Alert>}

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-cyberborder bg-cyberpanel p-4">
        <p className="text-sm text-cybertext">
          {counts.accepted} accepted · {counts.draft} to review · {counts.needs_answer} need your answer · {counts.rejected} rejected
        </p>
        <div className="flex flex-wrap gap-2">
          {highDrafts.length > 0 && (
            <Button size="sm" variant="secondary" disabled={busy} onClick={() => review(highDrafts.map((a) => a.id), "accept")}>
              Accept {highDrafts.length} high-confidence draft{highDrafts.length === 1 ? "" : "s"}
            </Button>
          )}
          {data.aiAvailable && counts.draft > 0 && (
            <Button size="sm" variant="secondary" disabled={busy} onClick={polish}>
              Improve wording with AI
            </Button>
          )}
          <Button size="sm" onClick={() => exportAs(data.questionnaire.source_format)}>
            Export .{data.questionnaire.source_format}
          </Button>
          <Button size="sm" variant="ghost" onClick={() => exportAs(data.questionnaire.source_format === "xlsx" ? "csv" : "xlsx")}>
            Export .{data.questionnaire.source_format === "xlsx" ? "csv" : "xlsx"}
          </Button>
        </div>
      </div>
      {unreviewed > 0 && <p className="text-xs text-warning">{unreviewed} answer{unreviewed === 1 ? " is" : "s are"} not reviewed yet. The export marks them &quot;Draft, not reviewed&quot; or &quot;Needs your answer&quot;.</p>}

      <SegmentedControl
        aria-label="Filter answers"
        value={filter}
        onChange={setFilter}
        options={[
          { value: "all", label: `All (${counts.total})` },
          { value: "needs_answer", label: `Needs your answer (${counts.needs_answer})` },
          { value: "draft", label: `To review (${counts.draft})` },
          { value: "accepted", label: `Accepted (${counts.accepted})` },
          { value: "rejected", label: `Rejected (${counts.rejected})` },
        ]}
      />

      {shown.length === 0 ? (
        <p className="text-sm text-cybermuted">Nothing here.</p>
      ) : (
        <ul className="space-y-3">
          {shown.map((a) => (
            <AnswerCard key={`${a.id}:${a.status}:${a.answer.length}`} a={a} busy={busy} onReview={(action, text) => review([a.id], action, text)} />
          ))}
        </ul>
      )}
    </div>
  );
}

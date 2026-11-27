"use client";

// Upload a supplier or insurer security questionnaire, confirm the question
// column, and draft answers from the customer's own evidence. Lists earlier
// questionnaires for reopening. Pro and above; the page shows it only then,
// and every route enforces it.

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { FileSpreadsheet, Upload } from "lucide-react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { Label } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  createQuestionnaire,
  deleteQuestionnaire,
  listQuestionnaires,
  previewQuestionnaire,
  readFileAsDataUrl,
  type QuestionnaireSummary,
  type SheetPreview,
} from "@/lib/questionnaire/client";

const MAX_BYTES = 5 * 1024 * 1024;
const selectClass = "h-10 w-full rounded-md border border-cyberborder bg-cyberbg px-3 text-sm text-cybertext focus-visible:outline-solid focus-visible:outline-2 focus-visible:outline-neon";

type Pending = { fileName: string; dataUrl: string; sheets: SheetPreview[]; sheet: number; column: number };

export default function QuestionnaireList({ token }: { token: string | null }) {
  const router = useRouter();
  const [items, setItems] = useState<QuestionnaireSummary[] | null>(null);
  const [enabled, setEnabled] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"reading" | "drafting" | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);

  useEffect(() => {
    if (!token) return;
    let live = true;
    listQuestionnaires(token)
      .then((res) => {
        if (!live) return;
        setItems(res.questionnaires);
        setEnabled(res.enabled);
      })
      .catch((err: Error) => {
        if (!live) return;
        setError(err.message);
        setItems([]);
      });
    return () => {
      live = false;
    };
  }, [token]);

  async function onFile(file: File | undefined) {
    if (!file || !token) return;
    setError(null);
    setPending(null);
    if (!/\.(xlsx|csv)$/i.test(file.name)) return setError("Upload an .xlsx or .csv file. Save older .xls files as .xlsx first.");
    if (file.size > MAX_BYTES) return setError("The file is larger than 5 MB.");
    setBusy("reading");
    try {
      const dataUrl = await readFileAsDataUrl(file);
      const res = await previewQuestionnaire(token, file.name, dataUrl);
      const best = res.sheets.reduce((b, s, i) => (s.questions > res.sheets[b].questions ? i : b), 0);
      setPending({ fileName: file.name, dataUrl, sheets: res.sheets, sheet: best, column: res.sheets[best].suggestedColumn });
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function draft() {
    if (!pending || !token) return;
    setBusy("drafting");
    setError(null);
    try {
      const sheet = pending.sheets[pending.sheet];
      const res = await createQuestionnaire(token, { fileName: pending.fileName, dataUrl: pending.dataUrl, sheet: sheet.name, questionColumn: pending.column });
      router.push(`/dashboard/questionnaires/${res.id}`);
    } catch (err) {
      setError((err as Error).message);
      setBusy(null);
    }
  }

  async function remove(q: QuestionnaireSummary) {
    if (!token || !window.confirm(`Delete "${q.name}" and its answers? Accepted answers in it won't be reused any more.`)) return;
    try {
      await deleteQuestionnaire(token, q.id);
      setItems((list) => (list ?? []).filter((x) => x.id !== q.id));
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const sheet = pending ? pending.sheets[pending.sheet] : null;

  return (
    <div className="space-y-6">
      {!enabled && <Alert variant="warning" title="Not available yet">Questionnaires aren&apos;t enabled on this server yet.</Alert>}
      {error && <Alert variant="danger">{error}</Alert>}

      <Card>
        <CardHeader className="block space-y-2">
          <CardTitle>Upload a questionnaire</CardTitle>
          <CardDescription>
            An .xlsx or .csv file from an insurer or customer, up to 5 MB. We draft each answer from your own evidence: your scans, Microsoft 365 or Google Workspace checks, email
            authentication, your Cyber Essentials answers, your devices and your uploaded documents. Anything we hold no evidence for is marked &quot;Needs your answer&quot;.
          </CardDescription>
        </CardHeader>
        <div className="mt-4 space-y-4">
          <label className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-cyberborder px-4 py-2 text-sm text-cybertext hover:border-neon hover:text-neon">
            <Upload className="size-4" aria-hidden="true" />
            {busy === "reading" ? "Reading…" : "Choose file"}
            <input
              type="file"
              accept=".xlsx,.csv,text/csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
              className="sr-only"
              aria-label="Questionnaire file"
              disabled={!token || !enabled || busy !== null}
              onChange={(e) => {
                void onFile(e.target.files?.[0]);
                e.target.value = "";
              }}
            />
          </label>

          {pending && sheet && (
            <div className="space-y-4 rounded-lg border border-cyberborder p-4">
              <p className="text-sm text-cybertext">
                <FileSpreadsheet className="mr-1 inline size-4 text-neon" aria-hidden="true" />
                {pending.fileName}: {sheet.rowCount} rows
              </p>
              {pending.sheets.length > 1 && (
                <div className="space-y-1">
                  <Label htmlFor="q-sheet">Sheet</Label>
                  <select
                    id="q-sheet"
                    className={selectClass}
                    value={pending.sheet}
                    onChange={(e) => {
                      const i = Number(e.target.value);
                      setPending({ ...pending, sheet: i, column: pending.sheets[i].suggestedColumn });
                    }}
                  >
                    {pending.sheets.map((s, i) => (
                      <option key={i} value={i}>
                        {s.name ?? `Sheet ${i + 1}`} ({s.rowCount} rows)
                      </option>
                    ))}
                  </select>
                </div>
              )}
              <div className="space-y-1">
                <Label htmlFor="q-column">Which column holds the questions?</Label>
                <select id="q-column" className={selectClass} value={pending.column} onChange={(e) => setPending({ ...pending, column: Number(e.target.value) })}>
                  {sheet.headers.map((h, i) => (
                    <option key={i} value={i}>
                      {h}
                      {i === sheet.suggestedColumn ? (sheet.confident ? " (detected)" : " (best guess)") : ""}
                    </option>
                  ))}
                </select>
                {!sheet.confident && pending.column === sheet.suggestedColumn && <p className="text-xs text-warning">We weren&apos;t sure which column holds the questions. Check the examples below.</p>}
              </div>
              <div>
                <p className="mb-1 text-xs text-cybermuted">First rows of that column:</p>
                <ul className="space-y-1 text-xs text-cybertext">
                  {sheet.sample.map((r, i) => (
                    <li key={i} className="truncate border-l-2 border-cyberborder pl-2">
                      {r[pending.column] || <span className="text-cybermuted">(empty)</span>}
                    </li>
                  ))}
                </ul>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button onClick={draft} disabled={busy !== null}>
                  {busy === "drafting" ? "Drafting answers…" : "Draft answers"}
                </Button>
                <Button variant="ghost" onClick={() => setPending(null)} disabled={busy !== null}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </div>
      </Card>

      <section aria-labelledby="q-list" className="space-y-3">
        <h2 id="q-list" className="text-lg font-semibold text-cybertext">
          Your questionnaires
        </h2>
        {items === null ? (
          <Skeleton className="h-24 w-full" />
        ) : items.length === 0 ? (
          <EmptyState icon={<FileSpreadsheet />} title="No questionnaires yet" description="Upload one above. Answers you accept are reused when the same question comes up again." />
        ) : (
          <ul className="divide-y divide-cyberborder rounded-xl border border-cyberborder bg-cyberpanel">
            {items.map((q) => (
              <li key={q.id} className="flex flex-wrap items-center justify-between gap-3 p-4">
                <div className="min-w-0">
                  <Link href={`/dashboard/questionnaires/${q.id}`} className="font-medium text-cybertext hover:text-neon">
                    {q.name}
                  </Link>
                  <p className="text-xs text-cybermuted">
                    Uploaded {q.created_at.slice(0, 10)} · {q.counts.accepted} of {q.counts.total} accepted · {q.counts.needs_answer} need your answer
                  </p>
                </div>
                <div className="flex gap-2">
                  <Link href={`/dashboard/questionnaires/${q.id}`} className="text-sm text-neon hover:underline">
                    Review
                  </Link>
                  <Button size="sm" variant="ghost" onClick={() => remove(q)}>
                    Delete
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

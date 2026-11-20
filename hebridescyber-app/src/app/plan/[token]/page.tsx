"use client";

// A shared fix plan, for whoever has the link (src/lib/fixPlans.ts). No
// account needed. Each item: what to fix, how, and its status; "I've done
// this" tells the owner, and an item shows as fixed once the owner's scans
// confirm it. The page never starts a scan.
import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import type { PublicPlan, PublicPlanItem } from "@/lib/fixPlans";

const STATUS_LABEL: Record<PublicPlanItem["status"], { text: string; className: string }> = {
  fixed: { text: "Fixed, confirmed by a scan", className: "border-neon/40 text-neon" },
  marked_done: { text: "Marked done, waiting for a scan to confirm", className: "border-warning/40 text-warning" },
  open: { text: "To do", className: "border-cyberborder text-cybermuted" },
};

function day(iso: string | null): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  return Number.isNaN(t) ? "" : new Date(t).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
}

function Item({ item, token, onChange }: { item: PublicPlanItem; token: string; onChange: () => void }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const status = STATUS_LABEL[item.status];

  async function mark(done: boolean) {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/plans/${token}/done`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ checkId: item.checkId, done, ...(done && note.trim() ? { note: note.trim() } : {}) }),
      });
      if (!res.ok) throw new Error(((await res.json().catch(() => ({}))) as { error?: string }).error ?? "Couldn't save that. Try again.");
      onChange();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <li className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h2 className="text-base font-semibold text-cybertext">
          <span className="mr-2 font-mono text-xs uppercase text-cybermuted">
            {item.position}. {item.severity}
          </span>
          {item.title}
        </h2>
        <span className={`rounded-sm border px-2 py-0.5 text-xs ${status.className}`}>
          {status.text}
          {item.status === "fixed" && item.fixedAt ? ` · ${day(item.fixedAt)}` : ""}
        </span>
      </div>
      {item.remediation ? (
        <div className="mt-3 whitespace-pre-line rounded-lg border border-cyberborder bg-cyberbg/50 p-3 text-sm text-cybertext/90">{item.remediation}</div>
      ) : (
        <p className="mt-3 text-sm text-cybermuted">Ask whoever sent this plan for the fix steps.</p>
      )}
      {item.status === "open" && (
        <div className="mt-3 space-y-2">
          <label className="block text-xs text-cybermuted" htmlFor={`note-${item.checkId}`}>
            Note for them (optional): what you changed
          </label>
          <textarea
            id={`note-${item.checkId}`}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            maxLength={1000}
            rows={2}
            className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext focus:border-neon focus:outline-hidden"
          />
          <Button size="sm" onClick={() => mark(true)} disabled={busy}>
            {busy ? "Saving…" : "I've done this"}
          </Button>
        </div>
      )}
      {item.status === "marked_done" && (
        <div className="mt-3 flex flex-wrap items-center gap-3 text-sm">
          <span className="text-cybermuted">
            You marked this done {day(item.markedDoneAt)}
            {item.note ? `: “${item.note}”` : ""}.
          </span>
          <Button size="sm" variant="ghost" onClick={() => mark(false)} disabled={busy}>
            Not done after all
          </Button>
        </div>
      )}
      {error && (
        <p role="alert" className="mt-2 text-sm text-danger">
          {error}
        </p>
      )}
    </li>
  );
}

export default function FixPlanPage() {
  const params = useParams<{ token: string }>();
  const token = params?.token ?? "";
  const [plan, setPlan] = useState<PublicPlan | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetch(`/api/plans/${token}`);
      const body = await res.json();
      if (!res.ok) throw new Error((body as { error?: string }).error ?? "This fix plan link isn't valid any more.");
      setPlan(body as PublicPlan);
    } catch (e) {
      setError((e as Error).message);
    }
  }, [token]);

  useEffect(() => {
    void load();
  }, [load]);

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-cyberbg px-6 text-center">
        <div>
          <p className="text-sm text-danger">{error}</p>
          <Link href="/" className="mt-4 inline-block text-sm text-neon underline">
            hebridescyber.co.uk
          </Link>
        </div>
      </div>
    );
  }
  if (!plan) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-cyberbg">
        <p className="font-mono text-sm text-cybermuted">Loading fix plan…</p>
      </div>
    );
  }

  const { progress } = plan;
  return (
    <div className="min-h-screen bg-cyberbg text-cybertext">
      <main className="relative mx-auto max-w-3xl space-y-6 px-4 py-10 sm:px-6">
        <div className="rounded-lg border border-neon/20 bg-neon/5 px-4 py-2 text-xs text-neon">Shared fix plan · no login needed</div>
        <div>
          <h1 className="break-words text-2xl font-bold text-cybertext">{plan.title}</h1>
          <p className="mt-1 break-all text-sm text-cybermuted">
            {plan.host} · shared {day(plan.createdAt)} · link works until {day(plan.expiresAt)}
          </p>
        </div>
        <div className="rounded-xl border border-cyberborder bg-cyberpanel p-4" aria-live="polite">
          <p className="text-sm text-cybertext">
            <b>
              {progress.fixed} of {progress.total}
            </b>{" "}
            fixed and confirmed{progress.markedDone ? `, ${progress.markedDone} marked done and waiting for a scan` : ""}.
          </p>
          <div className="mt-2 flex h-2 overflow-hidden rounded-full bg-cyberborder" aria-hidden="true">
            <div className="bg-neon" style={{ width: `${(progress.fixed / Math.max(1, progress.total)) * 100}%` }} />
            <div className="bg-warning" style={{ width: `${(progress.markedDone / Math.max(1, progress.total)) * 100}%` }} />
          </div>
        </div>
        <ol className="space-y-4">
          {plan.items.map((item) => (
            <Item key={item.checkId} item={item} token={token} onChange={load} />
          ))}
        </ol>
        <p className="border-t border-cyberborder pt-4 text-center text-xs text-cybermuted">
          Prepared with <Link href="/" className="text-neon hover:underline">Hebrides Cyber</Link>. An item shows as fixed once a scan of the site confirms it.
        </p>
      </main>
    </div>
  );
}

"use client";

// "Share a fix plan" on the scan report (Agency): pick findings, get a link
// for the client, their IT supplier or a developer, and see each plan's
// progress for this site (src/lib/fixPlans.ts). The link is shown once.
import { useCallback, useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { ViewFinding } from "./ScanReportView";

type PlanSummary = {
  id: string;
  title: string;
  host: string;
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
  progress: { fixed: number; markedDone: number; open: number; total: number };
};

const PRESELECT = 5;
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function day(iso: string): string {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? "" : new Date(t).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
}

export function FixPlanShare({ scanId, host, token, findings }: { scanId: string; host: string; token: string; findings: ViewFinding[] }) {
  const candidates = useMemo(
    () =>
      findings
        .filter((f): f is ViewFinding & { checkId: string } => Boolean(f.checkId) && f.status !== "fixed" && !f.triage && f.severity !== "info")
        .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]),
    [findings]
  );
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(() => new Set(candidates.slice(0, PRESELECT).map((f) => f.checkId)));
  const [title, setTitle] = useState("");
  const [days, setDays] = useState(90);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [link, setLink] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [plans, setPlans] = useState<PlanSummary[]>([]);
  // null until the list answers; false on 403 (not on Agency) or failure, so
  // the card shows only to accounts that can use it.
  const [allowed, setAllowed] = useState<boolean | null>(null);

  const loadPlans = useCallback(async () => {
    try {
      const res = await fetch(`/api/fix-plans?host=${encodeURIComponent(host)}`, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) {
        const now = Date.now();
        setPlans(((await res.json()) as { plans: PlanSummary[] }).plans.filter((p) => !p.revokedAt && Date.parse(p.expiresAt) > now));
        setAllowed(true);
      } else {
        setAllowed(false);
      }
    } catch {
      setAllowed(false);
    }
  }, [host, token]);

  useEffect(() => {
    void loadPlans();
  }, [loadPlans]);

  async function create() {
    setBusy(true);
    setError(null);
    setLink(null);
    try {
      const ordered = candidates.filter((f) => selected.has(f.checkId)).map((f) => f.checkId);
      const res = await fetch("/api/fix-plans", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ scanId, checkIds: ordered, expiresInDays: days, ...(title.trim() ? { title: title.trim() } : {}) }),
      });
      const body = (await res.json().catch(() => ({}))) as { url?: string; error?: string };
      if (!res.ok || !body.url) throw new Error(body.error ?? "Couldn't create the plan.");
      setLink(body.url);
      await loadPlans();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    const res = await fetch(`/api/fix-plans/${id}`, { method: "DELETE", headers: { Authorization: `Bearer ${token}` } });
    if (res.ok) await loadPlans();
  }

  async function copy() {
    if (!link) return;
    try {
      await navigator.clipboard.writeText(link);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  const live = plans;
  if (!allowed || (candidates.length === 0 && live.length === 0)) return null;

  return (
    <Card className="no-print" aria-labelledby="fix-plan-heading">
      <CardHeader>
        <div>
          <CardTitle id="fix-plan-heading">share a fix plan</CardTitle>
          <CardDescription className="mt-1">
            Send chosen findings to whoever does the work, by link, no account needed. They can mark items done; each shows as fixed once a scan confirms it.
          </CardDescription>
        </div>
        {!open && candidates.length > 0 && (
          <Button size="sm" variant="secondary" onClick={() => setOpen(true)}>
            Share a fix plan
          </Button>
        )}
      </CardHeader>

      {open && (
        <div className="space-y-3">
          <div className="flex flex-wrap gap-3">
            <label className="min-w-0 flex-1 text-xs text-cybermuted">
              Title (optional)
              <input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                maxLength={200}
                placeholder={`Fix plan for ${host}`}
                className="mt-1 block w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-1.5 text-sm text-cybertext focus:border-neon focus:outline-hidden"
              />
            </label>
            <label className="text-xs text-cybermuted">
              Link works for
              <select value={days} onChange={(e) => setDays(Number(e.target.value))} className="mt-1 block rounded-md border border-cyberborder bg-cyberbg px-3 py-1.5 text-sm text-cybertext">
                <option value={30}>30 days</option>
                <option value={90}>90 days</option>
                <option value={180}>180 days</option>
              </select>
            </label>
          </div>
          <ul className="max-h-72 divide-y divide-cyberborder overflow-y-auto rounded-lg border border-cyberborder">
            {candidates.map((f) => (
              <li key={f.checkId}>
                <label className="flex cursor-pointer items-center gap-3 px-3 py-2 text-sm hover:bg-cybertext/5">
                  <input
                    type="checkbox"
                    className="h-4 w-4 accent-neon"
                    checked={selected.has(f.checkId)}
                    onChange={() =>
                      setSelected((prev) => {
                        const next = new Set(prev);
                        if (next.has(f.checkId)) next.delete(f.checkId);
                        else next.add(f.checkId);
                        return next;
                      })
                    }
                  />
                  <span className="w-16 shrink-0 font-mono text-[11px] uppercase text-cybermuted">{f.severity}</span>
                  <span className="min-w-0 flex-1 truncate text-cybertext/90" title={f.title}>{f.title}</span>
                </label>
              </li>
            ))}
          </ul>
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" onClick={create} disabled={busy || selected.size === 0}>
              {busy ? "Creating…" : `Create link for ${selected.size} item${selected.size === 1 ? "" : "s"}`}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setOpen(false)}>
              Cancel
            </Button>
          </div>
          {error && <p role="alert" className="text-sm text-danger">{error}</p>}
          {link && (
            <div className="rounded-lg border border-neon/30 bg-neon/5 p-3 text-sm" role="status">
              <p className="mb-1 text-cybertext">Here&apos;s the link. Copy it now: for safety we don&apos;t show it again.</p>
              <div className="flex flex-wrap items-center gap-2">
                <code className="min-w-0 flex-1 break-all text-xs text-neon">{link}</code>
                <Button size="sm" variant="secondary" onClick={copy}>
                  {copied ? "Copied" : "Copy link"}
                </Button>
              </div>
            </div>
          )}
        </div>
      )}

      {live.length > 0 && (
        <div className="mt-4">
          <p className="mb-2 text-xs uppercase tracking-wide text-cybermuted">Shared plans for this site</p>
          <ul className="space-y-2">
            {live.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-cyberborder px-3 py-2 text-sm">
                <span className="min-w-0 text-cybertext">
                  {p.title} <span className="text-cybermuted">· {p.progress.fixed} of {p.progress.total} fixed{p.progress.markedDone ? `, ${p.progress.markedDone} marked done` : ""} · until {day(p.expiresAt)}</span>
                </span>
                <Button size="sm" variant="ghost" onClick={() => revoke(p.id)}>
                  Revoke link{" "}
                  <span className="sr-only">for {p.title}</span>
                </Button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}

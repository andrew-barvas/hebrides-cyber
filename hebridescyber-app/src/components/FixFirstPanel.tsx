"use client";

// Dashboard overview: the top of the estate "fix this first" list (P1-2) —
// open findings across every site, ranked by estatePriority.ts, each with the
// plain-English reason for its place. Data from GET /api/findings?sort=priority.
//
// Renders nothing until the data is back, and nothing before migration 043
// (no finding lifecycle). A failed load says so rather than showing an empty
// list, which would read as "nothing to fix".
import { useEffect, useState } from "react";
import Link from "next/link";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { Priority } from "@/lib/estatePriority";
import type { FindingRow } from "@/lib/findingsView";

export const FIX_FIRST_PREVIEW = 5;

type Item = FindingRow & { priority: Priority };
type State = { kind: "loading" } | { kind: "hidden" } | { kind: "error" } | { kind: "ready"; items: Item[]; total: number; complete: boolean };

const SEVERITY_CLASS: Record<FindingRow["severity"], string> = {
  critical: "text-danger",
  high: "text-danger",
  medium: "text-warning",
  low: "text-cybermuted",
  info: "text-cybermuted",
};

export default function FixFirstPanel({ token }: { token: string | null }) {
  const [state, setState] = useState<State>({ kind: "loading" });

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    fetch(`/api/findings?sort=priority&view=rows&pageSize=${FIX_FIRST_PREVIEW}`, { headers: { Authorization: `Bearer ${token}` } })
      .then(async (res): Promise<State> => {
        if (!res.ok) return { kind: "error" };
        const body = (await res.json()) as { available?: boolean; items?: Item[]; totalFindings?: number; priorityComplete?: boolean; truncated?: boolean };
        if (!body.available) return { kind: "hidden" };
        return { kind: "ready", items: body.items ?? [], total: body.totalFindings ?? 0, complete: body.priorityComplete !== false && !body.truncated };
      })
      .catch((): State => ({ kind: "error" }))
      .then((next) => {
        if (!cancelled) setState(next);
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  if (state.kind === "loading" || state.kind === "hidden") return null;

  return (
    <Card>
      <CardHeader>
        <div className="min-w-0">
          <CardTitle as="h2">fix this first</CardTitle>
          <CardDescription className="mt-1">
            Open findings across all your sites, most urgent first. Set how critical each site is under Assets.
          </CardDescription>
        </div>
        {state.kind === "ready" && state.total > 0 && (
          <Link href="/dashboard/findings?sort=priority" className="text-sm text-neon hover:underline">
            See all {state.total}
          </Link>
        )}
      </CardHeader>
      {state.kind === "error" ? (
        <p role="alert" className="text-sm text-danger">
          Couldn&apos;t load your priority list. Refresh to try again.
        </p>
      ) : state.items.length === 0 ? (
        <p className="text-sm text-cybermuted">Nothing open to fix across your sites.</p>
      ) : (
        <>
          <ol className="divide-y divide-cyberborder" aria-label="Findings to fix first">
            {state.items.map((f) => (
              <li key={f.key} className="flex items-start gap-3 py-2">
                <span className="w-6 shrink-0 font-mono text-sm font-semibold text-neon" aria-hidden="true">
                  {f.priority.rank}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-cybertext">
                    <span className={`mr-1.5 font-mono text-[11px] uppercase ${SEVERITY_CLASS[f.severity]}`}>{f.severity}</span>
                    {f.scanId ? (
                      <Link href={`/dashboard/scans/${f.scanId}`} className="hover:underline">
                        {f.title}
                      </Link>
                    ) : (
                      f.title
                    )}
                  </p>
                  <p className="break-all text-xs text-cybermuted">{f.host}</p>
                  <p className="text-xs text-cybertext/80">Why here: {f.priority.reason}</p>
                </div>
              </li>
            ))}
          </ol>
          {!state.complete && (
            <p className="mt-2 text-xs text-warning">Some data couldn&apos;t be read, so this ranking may be incomplete.</p>
          )}
        </>
      )}
    </Card>
  );
}

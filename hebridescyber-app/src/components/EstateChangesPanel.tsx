"use client";

// Dashboard overview: what changed across every site over the last 7, 30 or
// 90 days (findings opened and fixed, what's open now, new hostnames). Data
// from GET /api/estate/changes (src/lib/estateDrift.ts).
//
// Renders nothing before migration 043 (no finding history). A failed load
// says so rather than showing zeros, which would read as "nothing changed".
import { useEffect, useState } from "react";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SegmentedControl } from "@/components/ui/segmented-control";
import type { EstateDrift, SeverityCounts } from "@/lib/estateDrift";

type Days = "7" | "30" | "90";
type State = { kind: "loading" } | { kind: "hidden" } | { kind: "error" } | { kind: "ready"; drift: EstateDrift };

const WINDOWS: readonly { value: Days; label: string }[] = [
  { value: "7", label: "7 days" },
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
];

function Breakdown({ counts }: { counts: SeverityCounts }) {
  const parts = (["critical", "high", "medium", "low"] as const).filter((s) => counts[s] > 0).map((s) => `${counts[s]} ${s}`);
  return <p className="text-xs text-cybermuted">{parts.length > 0 ? parts.join(", ") : "none"}</p>;
}

export default function EstateChangesPanel({ token }: { token: string | null }) {
  const [days, setDays] = useState<Days>("30");
  const [state, setState] = useState<State>({ kind: "loading" });

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    fetch(`/api/estate/changes?days=${days}`, { headers: { Authorization: `Bearer ${token}` } })
      .then(async (res): Promise<State> => {
        if (!res.ok) return { kind: "error" };
        const body = (await res.json()) as { available?: boolean } & Partial<EstateDrift>;
        if (!body.available) return { kind: "hidden" };
        return { kind: "ready", drift: body as EstateDrift };
      })
      .catch((): State => ({ kind: "error" }))
      .then((next) => {
        if (!cancelled) setState(next);
      });
    return () => {
      cancelled = true;
    };
  }, [token, days]);

  if (state.kind === "hidden") return null;

  return (
    <Card>
      <CardHeader>
        <div className="min-w-0">
          <CardTitle as="h2">what changed</CardTitle>
          <CardDescription className="mt-1">Across all your sites. A finding counts as fixed when a later scan that could see it no longer did.</CardDescription>
        </div>
        <SegmentedControl aria-label="Time window" value={days} onChange={setDays} options={WINDOWS} />
      </CardHeader>
      {state.kind === "loading" ? (
        <p className="text-sm text-cybermuted">Loading…</p>
      ) : state.kind === "error" ? (
        <p role="alert" className="text-sm text-danger">
          Couldn&apos;t load what changed. Refresh to try again.
        </p>
      ) : (
        <div className="space-y-4">
          <dl className="grid gap-3 sm:grid-cols-3">
            <div>
              <dt className="text-xs uppercase tracking-wide text-cybermuted">New findings</dt>
              <dd className="text-2xl font-bold text-cybertext">{state.drift.opened.total}</dd>
              <dd>
                <Breakdown counts={state.drift.opened} />
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-cybermuted">Fixed</dt>
              <dd className="text-2xl font-bold text-neon">{state.drift.fixed.total}</dd>
              <dd>
                <Breakdown counts={state.drift.fixed} />
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-cybermuted">Open now</dt>
              <dd className="text-2xl font-bold text-cybertext">{state.drift.openNow.total}</dd>
              <dd>
                <Breakdown counts={state.drift.openNow} />
              </dd>
            </div>
          </dl>
          {state.drift.notableOpened.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-cybertext">New critical and high findings</h3>
              <ul className="mt-1 space-y-1 text-sm">
                {state.drift.notableOpened.map((n) => (
                  <li key={`${n.host} ${n.checkId}`}>
                    <span className="mr-1.5 font-mono text-[11px] uppercase text-danger">{n.severity}</span>
                    {n.title} <span className="break-all text-xs text-cybermuted">({n.host})</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {state.drift.newHosts.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-cybertext">New hostnames found</h3>
              <p className="mt-1 break-all text-sm text-cybertext/80">{state.drift.newHosts.join(", ")}</p>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

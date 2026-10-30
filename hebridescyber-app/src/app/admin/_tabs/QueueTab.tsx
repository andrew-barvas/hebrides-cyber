"use client";

import { useCallback, useEffect, useState } from "react";
import { QueueData, reltime, apiFetch, StatCard } from "../_shared";

export default function QueueTab({ token }: { token: string }) {
  const [data, setData] = useState<QueueData | null>(null);
  const [recovering, setRecovering] = useState(false);
  const [recoverMsg, setRecoverMsg] = useState<string | null>(null);
  const [retryingScanId, setRetryingScanId] = useState<string | null>(null);

  const load = useCallback(() => {
    apiFetch<QueueData>("/api/admin/queue", token).then(setData).catch(() => {});
  }, [token]);

  useEffect(() => {
    load();
    const iv = setInterval(load, 5_000);
    return () => clearInterval(iv);
  }, [load]);

  const recoverStale = async () => {
    setRecovering(true);
    setRecoverMsg(null);
    try {
      const result = await apiFetch<{ resetCount: number }>("/api/admin/queue", token, { method: "PATCH" });
      setRecoverMsg(result.resetCount > 0 ? `Recovered ${result.resetCount} stuck job(s).` : "No stuck jobs found.");
      load();
    } catch (e) {
      setRecoverMsg((e as Error).message);
    } finally {
      setRecovering(false);
    }
  };

  const retryJob = async (scanId: string | null) => {
    if (!scanId) return;
    setRetryingScanId(scanId);
    try {
      await apiFetch("/api/admin/scans", token, { method: "PATCH", body: JSON.stringify({ scanId, action: "retry" }) });
      load();
    } catch { /* no-op */ } finally {
      setRetryingScanId(null);
    }
  };

  if (!data) return <p className="font-mono text-sm text-cybermuted">// loading…</p>;

  if (!data.configured) {
    return (
      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-6">
        <p className="font-semibold text-cybertext/80">Queue data unavailable</p>
        <p className="mt-1 text-sm text-cybertext/50">{data.note ?? "Could not load scan_jobs."}</p>
      </div>
    );
  }

  const { stats, jobs } = data;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-3">
        <p className="font-mono text-xs text-cybermuted">// auto-refreshes every 5 s</p>
        <div className="flex items-center gap-2">
          {recoverMsg && <span className="text-xs text-cybertext/50">{recoverMsg}</span>}
          <button
            onClick={recoverStale}
            disabled={recovering}
            className="rounded-sm border border-cyberborder px-3 py-1 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-40 transition-colors"
            title="Reset jobs stuck 'running' for longer than any live scan can take (390 minutes) back to pending, without waiting for the next scheduled worker run."
          >
            {recovering ? "Recovering…" : "Recover stuck jobs"}
          </button>
        </div>
      </div>

      {stats && (
        <div className="grid grid-cols-5 gap-3">
          {(["active", "waiting", "delayed", "completed", "failed"] as const).map((k) => (
            <StatCard key={k} label={k} value={stats[k]} />
          ))}
        </div>
      )}

      {jobs && (
        <div className="space-y-4">
          {(["active", "waiting", "failed"] as const).map((state) => {
            const list = jobs[state] ?? [];
            if (list.length === 0) return null;
            return (
              <div key={state} className="rounded-xl border border-cyberborder bg-cyberpanel overflow-hidden">
                <div className="border-b border-cyberborder bg-cyberbg px-4 py-2.5 font-mono text-xs text-cybermuted uppercase tracking-wide">
                  {state} ({list.length})
                </div>
                {list.map((j) => (
                  <div key={j.id} className="flex items-center gap-4 border-b border-cyberborder/40 px-4 py-3 last:border-0">
                    <div className="flex-1 min-w-0">
                      <p className="truncate font-mono text-xs text-neon">{j.targetUrl}</p>
                      <p className="text-xs text-cybermuted">scan: {j.scanId?.slice(0, 8)}…</p>
                    </div>
                    {state === "active" && (
                      <div className="w-24">
                        <div className="h-1.5 rounded-full bg-cyberborder">
                          <div
                            className="h-1.5 rounded-full bg-neon transition-all shadow-glowsm"
                            style={{ width: `${j.progress ?? 0}%` }}
                          />
                        </div>
                        <p className="mt-0.5 text-right font-mono text-xs text-cybermuted">{j.progress ?? 0}%</p>
                      </div>
                    )}
                    <p className="text-xs text-cybermuted whitespace-nowrap">
                      {state === "active" && j.startedAt ? `claimed ${reltime(j.startedAt)}` : j.addedAt ? reltime(j.addedAt) : ""}
                    </p>
                    {state === "failed" && j.scanId && (
                      <button
                        onClick={() => retryJob(j.scanId)}
                        disabled={retryingScanId === j.scanId}
                        className="rounded-sm bg-seafoam/10 px-2 py-0.5 text-xs text-seafoam hover:bg-seafoam/20 disabled:opacity-40 transition-colors"
                      >
                        {retryingScanId === j.scanId ? "Retrying…" : "Retry"}
                      </button>
                    )}
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

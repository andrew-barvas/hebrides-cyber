"use client";

import { useCallback, useEffect, useState } from "react";
import { ScanRow, statusBadge, reltime, apiFetch, AdminInput, AdminSelect } from "../_shared";

export default function ScansTab({ token }: { token: string }) {
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const PAGE_SIZE = 50;

  const load = useCallback(async (q: string, s: string, p: number) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: String(p) });
      if (q) params.set("search", q);
      if (s) params.set("status", s);
      const data = await apiFetch<{ scans: ScanRow[] }>(`/api/admin/scans?${params}`, token);
      setScans(data.scans);
    } catch { /* no-op */ } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { load(search, statusFilter, page); }, [search, statusFilter, page, load]);

  const action = async (scanId: string, act: "cancel" | "retry") => {
    await apiFetch("/api/admin/scans", token, {
      method: "PATCH",
      body: JSON.stringify({ scanId, action: act }),
    });
    load(search, statusFilter, page);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <AdminInput
          type="search"
          placeholder="Filter by target URL…"
          className="flex-1 min-w-48"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1); }}
        />
        <AdminSelect
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
        >
          <option value="">All statuses</option>
          <option value="pending">Pending</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
        </AdminSelect>
      </div>

      <div className="overflow-x-auto rounded-xl border border-cyberborder bg-cyberpanel">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-cyberborder bg-cyberbg text-left text-xs text-cybermuted">
              <th className="px-4 py-3">Target</th>
              <th className="px-4 py-3">Owner</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Score</th>
              <th className="px-4 py-3">Created</th>
              <th className="px-4 py-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center font-mono text-sm text-cybermuted">// loading…</td></tr>
            ) : scans.length === 0 ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-sm text-cybermuted">No scans found</td></tr>
            ) : (
              scans.map((s) => (
                <tr key={s.id} className="border-b border-cyberborder/50 hover:bg-cybertext/5 transition-colors">
                  <td className="px-4 py-2.5 font-mono text-xs max-w-48">
                    <a href={`/dashboard/scans/${s.id}`} className="block truncate text-neon hover:underline">{s.targetUrl}</a>
                    {s.status === "failed" && s.errorDetail && (
                      <p className="mt-0.5 truncate text-[11px] text-red-400/80" title={s.errorDetail}>{s.errorDetail}</p>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-cybertext/50 max-w-36 truncate">{s.ownerEmail}</td>
                  <td className="px-4 py-2.5">{statusBadge(s.status)}</td>
                  <td className="px-4 py-2.5 text-sm font-medium font-mono">
                    {s.score !== null ? (
                      <span className={s.score >= 70 ? "text-neon" : s.score >= 40 ? "text-amber-400" : "text-red-400"}>
                        {s.score}
                      </span>
                    ) : "—"}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-cybermuted">{reltime(s.createdAt)}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex gap-1">
                      {(s.status === "running" || s.status === "pending") && (
                        <button onClick={() => action(s.id, "cancel")} className="rounded-sm bg-red-400/10 px-2 py-0.5 text-xs text-red-400 hover:bg-red-400/20 transition-colors">
                          Cancel
                        </button>
                      )}
                      {s.status === "failed" && (
                        <button onClick={() => action(s.id, "retry")} className="rounded-sm bg-seafoam/10 px-2 py-0.5 text-xs text-seafoam hover:bg-seafoam/20 transition-colors">
                          Retry
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="flex justify-end gap-2">
        <button disabled={page === 1} onClick={() => setPage((p) => p - 1)} className="rounded-sm border border-cyberborder px-3 py-1 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-30 transition-colors">← Prev</button>
        <span className="px-2 py-1 font-mono text-xs text-cybermuted">Page {page}</span>
        <button disabled={scans.length < PAGE_SIZE} onClick={() => setPage((p) => p + 1)} className="rounded-sm border border-cyberborder px-3 py-1 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-30 transition-colors">Next →</button>
      </div>
    </div>
  );
}

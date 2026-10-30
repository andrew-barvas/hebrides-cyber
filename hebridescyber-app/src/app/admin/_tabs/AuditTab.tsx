"use client";

import { useCallback, useEffect, useState } from "react";
import { AUDIT_CATEGORIES } from "@/lib/auditFilters";
import { AuditLog, reltime, apiFetch, AdminInput, AdminSelect } from "../_shared";

export default function AuditTab({ token }: { token: string }) {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [search, setSearch] = useState("");
  const [actor, setActor] = useState("");
  const [category, setCategory] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const PAGE_SIZE = 50;

  const load = useCallback(
    async (q: string, a: string, cat: string, f: string, t: string, p: number) => {
      const params = new URLSearchParams({ page: String(p) });
      if (q) params.set("search", q);
      if (a) params.set("actor", a);
      if (cat) params.set("category", cat);
      if (f) params.set("from", f);
      if (t) params.set("to", t);
      apiFetch<{ logs: AuditLog[]; total: number }>(`/api/admin/audit?${params}`, token)
        .then((d) => { setLogs(d.logs); setTotal(d.total); })
        .catch(() => {});
    },
    [token]
  );

  useEffect(() => { load(search, actor, category, from, to, page); }, [search, actor, category, from, to, page, load]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <AdminInput
          type="search"
          placeholder="Filter by action…"
          className="flex-1 min-w-36"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1); }}
        />
        <AdminInput
          type="search"
          placeholder="Filter by actor email…"
          className="flex-1 min-w-36"
          value={actor}
          onChange={(e) => { setActor(e.target.value); setPage(1); }}
        />
        <AdminSelect value={category} onChange={(e) => { setCategory(e.target.value); setPage(1); }}>
          <option value="">All categories</option>
          {AUDIT_CATEGORIES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
        </AdminSelect>
        <label className="flex items-center gap-1 text-xs text-cybermuted">
          From
          <AdminInput type="date" value={from} onChange={(e) => { setFrom(e.target.value); setPage(1); }} />
        </label>
        <label className="flex items-center gap-1 text-xs text-cybermuted">
          To
          <AdminInput type="date" value={to} onChange={(e) => { setTo(e.target.value); setPage(1); }} />
        </label>
        <span className="font-mono text-xs text-cybermuted">{total} events</span>
      </div>

      <div className="overflow-x-auto rounded-xl border border-cyberborder bg-cyberpanel">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-cyberborder bg-cyberbg text-left text-xs text-cybermuted">
              <th className="px-4 py-3">When</th>
              <th className="px-4 py-3">Actor</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Resource</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 ? (
              <tr><td colSpan={4} className="px-4 py-8 text-center font-mono text-sm text-cybermuted">// no audit events found</td></tr>
            ) : (
              logs.map((l) => (
                <tr key={l.id} className="border-b border-cyberborder/50 hover:bg-cybertext/5 transition-colors">
                  <td className="px-4 py-2 font-mono text-xs text-cybermuted whitespace-nowrap">{reltime(l.created_at)}</td>
                  <td className="px-4 py-2 font-mono text-xs text-cybertext/70 max-w-40 truncate">{l.actor_email}</td>
                  <td className="px-4 py-2 font-mono text-xs text-neon">{l.action}</td>
                  <td className="px-4 py-2 text-xs text-cybertext/50">
                    {l.resource_type}{l.resource_id ? ` · ${l.resource_id.slice(0, 8)}…` : ""}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {total > PAGE_SIZE && (
        <div className="flex justify-end gap-2">
          <button disabled={page === 1} onClick={() => setPage((p) => p - 1)} className="rounded-sm border border-cyberborder px-3 py-1 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-30 transition-colors">← Prev</button>
          <span className="px-2 py-1 font-mono text-xs text-cybermuted">Page {page}</span>
          <button disabled={page * PAGE_SIZE >= total} onClick={() => setPage((p) => p + 1)} className="rounded-sm border border-cyberborder px-3 py-1 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-30 transition-colors">Next →</button>
        </div>
      )}
    </div>
  );
}

"use client";

import { useEffect, useState } from "react";
import { teamSizeLabel, budgetRangeLabel } from "@/lib/contactOptions";
import { ContactEnquiry, reltime, apiFetch } from "../_shared";

export default function ContactsTab({ token }: { token: string }) {
  const [enquiries, setEnquiries] = useState<ContactEnquiry[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const PAGE_SIZE = 25;

  useEffect(() => {
    apiFetch<{ enquiries: ContactEnquiry[]; total: number }>(`/api/admin/contacts?page=${page}`, token)
      .then((d) => { setEnquiries(d.enquiries); setTotal(d.total); setLoading(false); })
      .catch((e) => { setErr(e.message); setLoading(false); });
  }, [token, page]);

  async function toggleRead(id: string, current: boolean) {
    try {
      await apiFetch("/api/admin/contacts", token, {
        method: "PATCH",
        body: JSON.stringify({ id, read: !current }),
      });
      setEnquiries((prev) =>
        prev.map((e) => e.id === id ? { ...e, read: !current } : e)
      );
    } catch { /* best-effort */ }
  }

  if (loading) return <p className="text-cybermuted text-sm font-mono">// loading…</p>;
  if (err) return <p className="text-red-400 text-sm">{err}</p>;
  if (total === 0)
    return (
      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-8 text-center">
        <p className="text-cybermuted text-sm">No contact enquiries yet.</p>
      </div>
    );

  const unread = enquiries.filter((e) => !e.read).length;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <p className="font-mono text-xs text-cybermuted">{total} enquiries</p>
        {unread > 0 && (
          <span className="rounded-full bg-neon/20 px-2 py-0.5 text-xs font-medium text-neon">
            {unread} unread
          </span>
        )}
      </div>

      <div className="space-y-2">
        {enquiries.map((e) => (
          <div
            key={e.id}
            className={`rounded-xl border bg-cyberpanel transition-colors ${e.read ? "border-cyberborder" : "border-neon/30"}`}
          >
            <button
              className="w-full px-5 py-4 text-left flex items-start justify-between gap-4"
              onClick={() => setExpanded(expanded === e.id ? null : e.id)}
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  {!e.read && <span className="h-2 w-2 rounded-full bg-neon flex-shrink-0" />}
                  <span className="font-medium text-cybertext text-sm">{e.name}</span>
                  <span className="font-mono text-xs text-cybermuted">{e.email}</span>
                </div>
                <p className="mt-1 text-xs text-cybertext/50 truncate max-w-lg">{e.message}</p>
              </div>
              <div className="flex-shrink-0 text-right">
                <p className="text-xs text-cybermuted">{reltime(e.created_at)}</p>
                {e.url && (
                  <p className="mt-0.5 font-mono text-xs text-neon/60 truncate max-w-[160px]">{e.url}</p>
                )}
                {/* Surfaced here (not just in the expanded view) so a real
                    budget answer is visible while just scanning the list —
                    otherwise collecting it is pointless. */}
                {e.budget_range && e.budget_range !== "unsure" && (
                  <p className="mt-0.5 text-xs font-semibold text-neon">{budgetRangeLabel(e.budget_range) ?? e.budget_range}</p>
                )}
              </div>
            </button>

            {expanded === e.id && (
              <div className="border-t border-cyberborder px-5 pb-5 pt-4 space-y-4">
                {(e.company || e.team_size || e.budget_range) && (
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-cybertext/60">
                    {e.company && <span><strong className="text-cybertext/80">Company:</strong> {e.company}</span>}
                    {e.team_size && <span><strong className="text-cybertext/80">Team size:</strong> {teamSizeLabel(e.team_size) ?? e.team_size}</span>}
                    {e.budget_range && <span><strong className="text-cybertext/80">Budget:</strong> {budgetRangeLabel(e.budget_range) ?? e.budget_range}</span>}
                  </div>
                )}
                <div className="rounded-lg bg-cyberbg border border-cyberborder p-4">
                  <p className="text-sm text-cybertext/80 leading-relaxed whitespace-pre-wrap">{e.message}</p>
                </div>
                <div className="flex flex-wrap gap-3 text-xs">
                  <a
                    href={`mailto:${e.email}?subject=Re: your Hebrides Cyber enquiry`}
                    className="rounded-md bg-neon px-4 py-2 font-semibold text-cyberbg hover:opacity-90 shadow-glowsm transition-opacity"
                  >
                    Reply by email
                  </a>
                  <button
                    onClick={() => toggleRead(e.id, e.read)}
                    className="rounded-md border border-cyberborder px-4 py-2 text-cybertext/60 hover:border-neon hover:text-neon transition-colors"
                  >
                    Mark as {e.read ? "unread" : "read"}
                  </button>
                  {e.url && (
                    <a
                      href={e.url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="rounded-md border border-cyberborder px-4 py-2 text-cybertext/60 hover:border-neon hover:text-neon transition-colors"
                    >
                      Visit site →
                    </a>
                  )}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {total > PAGE_SIZE && (
        <div className="flex justify-end gap-2">
          <button disabled={page === 1} onClick={() => setPage((p) => p - 1)} className="rounded border border-cyberborder px-3 py-1 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-30 transition-colors">← Prev</button>
          <span className="px-2 py-1 font-mono text-xs text-cybermuted">Page {page}</span>
          <button disabled={page * PAGE_SIZE >= total} onClick={() => setPage((p) => p + 1)} className="rounded border border-cyberborder px-3 py-1 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-30 transition-colors">Next →</button>
        </div>
      )}
    </div>
  );
}

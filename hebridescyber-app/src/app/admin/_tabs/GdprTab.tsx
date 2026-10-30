"use client";

import { useEffect, useState } from "react";
import { reltime, apiFetch } from "../_shared";

type DeletionRequest = {
  id: string;
  owner: string;
  email: string | null;
  requestedAt: string;
  dueAt: string;
  overdue: boolean;
  wording: string;
};

export default function DeletionRequestsTab({ token }: { token: string }) {
  const [requests, setRequests] = useState<DeletionRequest[]>([]);
  const [overdue, setOverdue] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    apiFetch<{ overdueCount: number; requests: DeletionRequest[] }>("/api/admin/deletion-requests", token)
      .then((d) => { setRequests(d.requests); setOverdue(d.overdueCount); setLoaded(true); })
      .catch((e) => setErr((e as Error).message));
  }, [token]);

  if (err) return <p className="text-sm text-red-400">{err}</p>;
  if (!loaded) return <p className="font-mono text-sm text-cybermuted">// loading…</p>;

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
        <h3 className="font-mono text-xs uppercase tracking-wide text-cybermuted">// right-to-erasure queue</h3>
        <p className="mt-2 text-xs text-cybertext/50">
          Pending erasure requests, soonest deadline first (/privacy promises action within 30 days).
          {overdue > 0 ? <span className="text-red-400"> {overdue} overdue.</span> : " None overdue."} Run
          {" "}<code className="rounded-sm bg-cyberbg px-1 text-cybertext/70">npm run account:erase</code> to action one — erasure is a deliberate operator step, not a button here.
        </p>
      </div>

      {requests.length === 0 ? (
        <p className="rounded-xl border border-cyberborder bg-cyberpanel p-8 text-center text-sm text-cybermuted">No pending erasure requests.</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-cyberborder bg-cyberpanel">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-cyberborder bg-cyberbg text-left text-xs text-cybermuted">
                <th className="px-4 py-3">Account</th>
                <th className="px-4 py-3">Requested</th>
                <th className="px-4 py-3">Deadline</th>
              </tr>
            </thead>
            <tbody>
              {requests.map((r) => (
                <tr key={r.id} className="border-b border-cyberborder/50">
                  <td className="px-4 py-2.5 font-mono text-xs text-cybertext/70">{r.email ?? r.owner}</td>
                  <td className="px-4 py-2.5 text-xs text-cybermuted">{reltime(r.requestedAt)}</td>
                  <td className={`px-4 py-2.5 text-xs font-medium ${r.overdue ? "text-red-400" : "text-cybertext/60"}`}>{r.wording}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

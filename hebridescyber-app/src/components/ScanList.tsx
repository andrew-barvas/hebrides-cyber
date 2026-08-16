"use client";

import { useState } from "react";
import Link from "next/link";

export type Scan = {
  id: string;
  target_url: string;
  status: "pending" | "running" | "completed" | "failed";
  created_at: string;
  score?: number | null;
  // Set only when this scan belongs to a team owner other than the current
  // viewer — see the "Team" section in Account. Own scans leave this unset
  // rather than showing "shared by you", which would just be noise.
  sharedByEmail?: string | null;
};

type Props = {
  scans: Scan[];
  onDelete?: (id: string) => Promise<void>;
};

export default function ScanList({ scans, onDelete }: Props) {
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  async function handleDelete(id: string) {
    if (confirmId !== id) {
      setConfirmId(id);
      return;
    }
    setDeletingId(id);
    setConfirmId(null);
    try {
      await onDelete?.(id);
    } finally {
      setDeletingId(null);
    }
  }

  if (scans.length === 0) {
    return (
      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-6 text-center">
        <p className="text-sm text-cybertext/50">No scans yet. Enter a URL above and click <strong className="text-cybertext/80">Run scan</strong>.</p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel overflow-hidden">
      <div className="px-5 py-3 border-b border-cyberborder">
        <h2 className="font-mono text-xs text-cybertext/40 uppercase tracking-wide">// recent scans</h2>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-cyberborder text-left bg-cyberbg/50">
              <th className="px-5 py-2.5 text-xs font-medium text-cybertext/40">Target</th>
              <th className="px-4 py-2.5 text-xs font-medium text-cybertext/40">Score</th>
              <th className="px-4 py-2.5 text-xs font-medium text-cybertext/40">Status</th>
              <th className="px-4 py-2.5 text-xs font-medium text-cybertext/40">Date</th>
              <th className="px-4 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={scan.id} className="border-b border-cyberborder/50 last:border-0 hover:bg-cyberbg/30 transition-colors">
                {/* Wraps rather than truncating — the full URL is the row's
                    primary identifier, and two scans of the same site often
                    differ only in the path. break-all so a long URL with no
                    natural break points still wraps instead of forcing the
                    table wider than its container. */}
                <td className="px-5 py-3 font-mono text-xs text-neon/80 break-all min-w-[220px]">
                  {scan.target_url}
                  {scan.sharedByEmail && (
                    <span className="mt-0.5 block font-sans text-[10px] font-normal text-cybertext/40">
                      shared by {scan.sharedByEmail}
                    </span>
                  )}
                </td>
                <td className="px-4 py-3">
                  {scan.score != null ? (
                    <ScoreBadge score={scan.score} />
                  ) : (
                    <span className="text-xs text-cybertext/20">—</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status={scan.status} />
                </td>
                <td className="px-4 py-3 text-xs text-cybertext/40 whitespace-nowrap">
                  {new Date(scan.created_at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })}
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center justify-end gap-3">
                    {scan.status === "completed" ? (
                      <Link
                        href={`/dashboard/scans/${scan.id}`}
                        className="text-xs font-medium text-neon hover:underline whitespace-nowrap"
                      >
                        View report →
                      </Link>
                    ) : (
                      <span className="text-xs text-cybertext/20">—</span>
                    )}
                    {onDelete && (
                      deletingId === scan.id ? (
                        <span className="text-xs text-cybertext/40">Deleting…</span>
                      ) : confirmId === scan.id ? (
                        <span className="flex items-center gap-1.5">
                          <button
                            onClick={() => handleDelete(scan.id)}
                            className="text-xs font-medium text-red-400 hover:underline"
                          >
                            Confirm
                          </button>
                          <span className="text-cybertext/20" aria-hidden="true">|</span>
                          <button
                            onClick={() => setConfirmId(null)}
                            className="text-xs text-cybertext/40 hover:text-cybertext/70"
                          >
                            Cancel
                          </button>
                        </span>
                      ) : (
                        <button
                          onClick={() => handleDelete(scan.id)}
                          className="text-xs text-cybertext/30 hover:text-red-400 transition-colors"
                          title="Delete scan"
                        >
                          Delete
                        </button>
                      )
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ScoreBadge({ score }: { score: number }) {
  const colour =
    score >= 80 ? "text-neon border-neon/30 bg-neon/10"
    : score >= 60 ? "text-yellow-400 border-yellow-400/30 bg-yellow-400/10"
    : score >= 40 ? "text-orange-400 border-orange-400/30 bg-orange-400/10"
    : "text-red-400 border-red-400/30 bg-red-400/10";
  return (
    <span className={`inline-block rounded-full border px-2 py-0.5 text-xs font-bold ${colour}`}>
      {score}/100
    </span>
  );
}

function StatusBadge({ status }: { status: Scan["status"] }) {
  const colours: Record<Scan["status"], string> = {
    pending:   "bg-cybertext/10 text-cybertext/60",
    running:   "bg-amber-400/10 text-amber-400",
    completed: "bg-neon/10 text-neon",
    failed:    "bg-red-400/10 text-red-400",
  };
  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${colours[status]}`}>
      {status}
    </span>
  );
}

"use client";

import { useState } from "react";
import Link from "next/link";

export type Scan = {
  id: string;
  target_url: string;
  status: "pending" | "queued" | "running" | "completed" | "failed";
  created_at: string;
  score?: number | null;
  sharedByEmail?: string | null;
};

type Props = {
  scans: Scan[];
  onDelete?: (id: string) => Promise<void>;
};

export default function ScanList({ scans, onDelete }: Props) {
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  async function handleDelete(id: string) {
    if (confirmId !== id) {
      setConfirmId(id);
      return;
    }
    setDeletingId(id);
    setConfirmId(null);
    setDeleteError(null);
    try {
      await onDelete?.(id);
    } catch (err) {
      // Previously uncaught — a delete failure (e.g. a policy or network
      // error) silently left the row sitting in the list with no
      // indication anything went wrong. Surface it instead.
      setDeleteError((err as Error).message || "Could not delete this scan — try again.");
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
        {deleteError && <p className="mt-1.5 text-xs text-red-400">{deleteError}</p>}
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
                <td className="px-5 py-3 font-mono text-xs text-neon/80 break-all min-w-[140px]">
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
                  {(scan.status === "queued" || scan.status === "running") && (
                    <span className="block text-[10px] text-cybertext/30 mt-0.5">
                      {formatElapsed(scan.created_at)} ago
                    </span>
                  )}
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
    queued:    "bg-blue-400/10 text-blue-400",
    running:   "bg-amber-400/10 text-amber-400",
    completed: "bg-neon/10 text-neon",
    failed:    "bg-red-400/10 text-red-400",
  };
  const labels: Record<Scan["status"], string> = {
    pending:   "pending",
    queued:    "queued",
    running:   "scanning",
    completed: "completed",
    failed:    "failed",
  };
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium ${colours[status]}`}>
      {(status === "queued" || status === "running") && (
        <span className="inline-block h-1.5 w-1.5 rounded-full bg-current animate-pulse" />
      )}
      {labels[status]}
    </span>
  );
}

function formatElapsed(isoDate: string): string {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(isoDate).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const remainingMins = minutes % 60;
  return remainingMins > 0 ? `${hours}h ${remainingMins}m` : `${hours}h`;
}

"use client";

import Link from "next/link";

export type Scan = {
  id: string;
  target_url: string;
  status: "pending" | "running" | "completed" | "failed";
  created_at: string;
  score?: number | null;
};

export default function ScanList({ scans }: { scans: Scan[] }) {
  if (scans.length === 0) {
    return (
      <div className="rounded-xl border border-slate-200 bg-white p-6 text-center">
        <p className="text-sm text-slate-500">No scans yet. Enter a URL above and click <strong>Run scan</strong>.</p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
      <div className="px-5 py-3 border-b border-slate-100">
        <h2 className="text-sm font-semibold text-atlantic">Recent scans</h2>
      </div>
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-slate-100 text-left bg-slate-50">
            <th className="px-5 py-2.5 text-xs font-medium text-slate-500">Target</th>
            <th className="px-4 py-2.5 text-xs font-medium text-slate-500">Score</th>
            <th className="px-4 py-2.5 text-xs font-medium text-slate-500">Status</th>
            <th className="px-4 py-2.5 text-xs font-medium text-slate-500">Date</th>
            <th className="px-4 py-2.5" />
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id} className="border-b border-slate-100 last:border-0">
              <td className="px-5 py-3 font-mono text-xs text-atlantic max-w-[180px] truncate">
                {scan.target_url}
              </td>
              <td className="px-4 py-3">
                {scan.score != null ? (
                  <ScoreBadge score={scan.score} />
                ) : (
                  <span className="text-xs text-slate-300">—</span>
                )}
              </td>
              <td className="px-4 py-3">
                <StatusBadge status={scan.status} />
              </td>
              <td className="px-4 py-3 text-xs text-slate-400 whitespace-nowrap">
                {new Date(scan.created_at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })}
              </td>
              <td className="px-4 py-3 text-right">
                {scan.status === "completed" ? (
                  <Link
                    href={`/dashboard/scans/${scan.id}`}
                    className="text-xs font-medium text-atlantic hover:underline"
                  >
                    View report →
                  </Link>
                ) : (
                  <span className="text-xs text-slate-300">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ScoreBadge({ score }: { score: number }) {
  const colour =
    score >= 80 ? "text-green-700 bg-green-50 border-green-200"
    : score >= 60 ? "text-yellow-700 bg-yellow-50 border-yellow-200"
    : score >= 40 ? "text-orange-700 bg-orange-50 border-orange-200"
    : "text-red-700 bg-red-50 border-red-200";
  return (
    <span className={`inline-block rounded-full border px-2 py-0.5 text-xs font-bold ${colour}`}>
      {score}/100
    </span>
  );
}

function StatusBadge({ status }: { status: Scan["status"] }) {
  const colours: Record<Scan["status"], string> = {
    pending:   "bg-slate-100 text-slate-600",
    running:   "bg-amber-100 text-amber-700",
    completed: "bg-green-100 text-green-700",
    failed:    "bg-red-100 text-red-700",
  };
  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${colours[status]}`}>
      {status}
    </span>
  );
}

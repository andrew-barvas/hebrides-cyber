"use client";

import Link from "next/link";

export type Scan = {
  id: string;
  target_url: string;
  status: "pending" | "running" | "completed" | "failed";
  created_at: string;
};

// Presentational component — takes scans as a prop so it can be reused with
// real Supabase data (dashboard) or mock data (local dev / Storybook-style
// testing) without changing this file.
export default function ScanList({ scans }: { scans: Scan[] }) {
  if (scans.length === 0) {
    return (
      <p className="text-sm text-slatedark/60">
        No scans yet. Run one from the dashboard to see results here.
      </p>
    );
  }

  return (
    <table className="w-full border-collapse text-sm">
      <thead>
        <tr className="border-b border-slate-200 text-left">
          <th className="py-2 pr-4">Target</th>
          <th className="py-2 pr-4">Status</th>
          <th className="py-2 pr-4">Created</th>
          <th className="py-2" />
        </tr>
      </thead>
      <tbody>
        {scans.map((scan) => (
          <tr key={scan.id} className="border-b border-slate-100">
            <td className="py-2 pr-4">{scan.target_url}</td>
            <td className="py-2 pr-4">
              <StatusBadge status={scan.status} />
            </td>
            <td className="py-2 pr-4 text-slatedark/60">
              {new Date(scan.created_at).toLocaleString()}
            </td>
            <td className="py-2">
              <Link
                href={`/dashboard/scans/${scan.id}`}
                className="text-atlantic hover:underline"
              >
                View report
              </Link>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function StatusBadge({ status }: { status: Scan["status"] }) {
  const colors: Record<Scan["status"], string> = {
    pending: "bg-slate-200 text-slate-700",
    running: "bg-amber-200 text-amber-800",
    completed: "bg-green-200 text-green-800",
    failed: "bg-red-200 text-red-800",
  };
  return (
    <span className={`rounded-full px-2 py-1 text-xs font-medium ${colors[status]}`}>
      {status}
    </span>
  );
}

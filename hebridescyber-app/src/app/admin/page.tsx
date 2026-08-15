"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { getSession } from "@/lib/auth";

type Customer = {
  id: string;
  email: string;
  companyName: string | null;
  isAdmin: boolean;
  plan: "none" | "basic" | "pro" | "agency";
  subscriptionStatus: string | null;
  scanCount: number;
  createdAt: string;
};

// Cross-customer view for staff — gated server-side by is_admin
// (src/pages/api/admin/overview.ts), not just hidden client-side. See
// npm run seed:users for how to get an admin account to view this with.
export default function AdminOverviewPage() {
  const [state, setState] = useState<"loading" | "unauthorized" | "signed-out" | "ready">("loading");
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [totals, setTotals] = useState<{ customers: number; activeSubscriptions: number; totalScans: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const session = await getSession();
      if (!session) {
        setState("signed-out");
        return;
      }

      const res = await fetch("/api/admin/overview", {
        headers: { Authorization: `Bearer ${session.access_token}` },
      });

      if (res.status === 403) {
        setState("unauthorized");
        return;
      }
      const body = await res.json();
      if (!res.ok) {
        setError(body.error ?? `Request failed (${res.status})`);
        setState("unauthorized");
        return;
      }

      setCustomers(body.customers);
      setTotals(body.totals);
      setState("ready");
    })();
  }, []);

  if (state === "loading") return <div className="px-6 py-16 text-center">Loading…</div>;

  if (state === "signed-out") {
    return (
      <div className="mx-auto max-w-md px-6 py-24 text-center">
        <h1 className="text-2xl font-bold text-atlantic">Sign in required</h1>
        <Link href="/login" className="mt-6 inline-block text-atlantic underline">
          Sign in
        </Link>
      </div>
    );
  }

  if (state === "unauthorized") {
    return (
      <div className="mx-auto max-w-md px-6 py-24 text-center">
        <h1 className="text-2xl font-bold text-atlantic">Admin access required</h1>
        <p className="mt-4 text-sm text-slatedark/70">
          {error ?? "This account isn't marked as an admin. Seed one with npm run seed:users, or set is_admin manually in Supabase."}
        </p>
        <Link href="/dashboard" className="mt-6 inline-block text-atlantic underline">
          Back to your dashboard
        </Link>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl px-6 py-16">
      <p className="mb-1 font-mono text-xs text-atlantic/60">// admin.overview()</p>
      <h1 className="mb-8 text-3xl font-bold text-atlantic">All Customers</h1>

      {totals && (
        <div className="mb-8 grid grid-cols-3 gap-4">
          <Stat label="Customers" value={totals.customers} />
          <Stat label="Active subscriptions" value={totals.activeSubscriptions} />
          <Stat label="Total scans" value={totals.totalScans} />
        </div>
      )}

      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-slate-200 text-left">
            <th className="py-2 pr-4">Email</th>
            <th className="py-2 pr-4">Company</th>
            <th className="py-2 pr-4">Plan</th>
            <th className="py-2 pr-4">Status</th>
            <th className="py-2 pr-4">Scans</th>
            <th className="py-2">Joined</th>
          </tr>
        </thead>
        <tbody>
          {customers.map((c) => (
            <tr key={c.id} className="border-b border-slate-100">
              <td className="py-2 pr-4">
                {c.email} {c.isAdmin && <span className="ml-1 rounded bg-atlantic/10 px-1.5 py-0.5 text-xs text-atlantic">admin</span>}
              </td>
              <td className="py-2 pr-4 text-slatedark/70">{c.companyName ?? "—"}</td>
              <td className="py-2 pr-4 capitalize">{c.plan}</td>
              <td className="py-2 pr-4 text-slatedark/70">{c.subscriptionStatus ?? "—"}</td>
              <td className="py-2 pr-4">{c.scanCount}</td>
              <td className="py-2 text-slatedark/60">{new Date(c.createdAt).toLocaleDateString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-slate-200 p-4">
      <p className="text-2xl font-bold text-atlantic">{value}</p>
      <p className="text-xs text-slatedark/60">{label}</p>
    </div>
  );
}

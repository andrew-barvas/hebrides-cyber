"use client";

import { useCallback, useEffect, useState } from "react";
import { Customer, CustomerDetail, statusBadge, reltime, apiFetch, UsageRow, AdminInput, AdminSelect } from "../_shared";

export default function CustomersTab({ token }: { token: string }) {
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [viewingId, setViewingId] = useState<string | null>(null);
  const PAGE_SIZE = 25;

  const load = useCallback(async (q: string, p: number) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: String(p) });
      if (q) params.set("search", q);
      const data = await apiFetch<{ customers: Customer[]; total: number }>(
        `/api/admin/customers?${params}`, token
      );
      setCustomers(data.customers);
      setTotal(data.total);
    } catch { /* no-op */ } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { load(search, page); }, [search, page, load]);

  if (viewingId) {
    return (
      <CustomerDetailPanel
        token={token}
        ownerId={viewingId}
        onClose={() => setViewingId(null)}
        onChanged={() => load(search, page)}
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <AdminInput
          type="search"
          placeholder="Search by email or company…"
          className="flex-1"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1); }}
        />
        <span className="font-mono text-xs text-cybermuted">{total} customers</span>
      </div>

      <div className="overflow-x-auto rounded-xl border border-cyberborder bg-cyberpanel">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-cyberborder bg-cyberbg text-left text-xs text-cybermuted">
              <th className="px-4 py-3">Email</th>
              <th className="px-4 py-3">Company</th>
              <th className="px-4 py-3">Plan</th>
              <th className="px-4 py-3">Sub status</th>
              <th className="px-4 py-3">Scans</th>
              <th className="px-4 py-3">Joined</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="px-4 py-8 text-center font-mono text-sm text-cybermuted">// loading…</td></tr>
            ) : customers.length === 0 ? (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-sm text-cybermuted">No customers found</td></tr>
            ) : (
              customers.map((c) => (
                <tr key={c.id} className="border-b border-cyberborder/50 hover:bg-cybertext/5 transition-colors">
                  <td className="px-4 py-2.5 font-mono text-xs text-neon">
                    {c.email}
                    {c.is_admin && (
                      <span className="ml-1 rounded bg-neon/10 px-1 text-[10px] text-neon">admin</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-cybertext/60">{c.company_name ?? "—"}</td>
                  <td className="px-4 py-2.5 capitalize text-cybertext/70">
                    {c.plan ?? "none"}
                    {c.plan_source === "admin" && (
                      <span className="ml-1 rounded bg-amber-400/10 px-1 text-[10px] normal-case text-amber-400">manual</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5">{c.subscription_status ? statusBadge(c.subscription_status) : "—"}</td>
                  <td className="px-4 py-2.5 text-cybertext/70">{c.scan_count}</td>
                  <td className="px-4 py-2.5 text-cybermuted">{reltime(c.created_at)}</td>
                  <td className="px-4 py-2.5">
                    <button onClick={() => setViewingId(c.id)} className="rounded border border-cyberborder px-2 py-0.5 text-xs text-cybertext/60 hover:border-neon hover:text-neon transition-colors">
                      View
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
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

const PLAN_OPTIONS = ["basic", "pro", "agency", "tier_a"] as const;
const STATUS_OPTIONS = ["active", "inactive", "past_due", "cancelled"] as const;

function CustomerDetailPanel({
  token, ownerId, onClose, onChanged,
}: {
  token: string;
  ownerId: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [detail, setDetail] = useState<CustomerDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [plan, setPlan] = useState<string>("basic");
  const [status, setStatus] = useState<string>("active");
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await apiFetch<CustomerDetail>(`/api/admin/customers/${ownerId}`, token);
      setDetail(data);
      setPlan(data.subscription?.plan ?? "basic");
      setStatus(data.subscription?.status ?? "active");
    } catch (e) {
      setError((e as Error).message);
    }
  }, [token, ownerId]);

  useEffect(() => { load(); }, [load]);

  const overridePlan = async () => {
    if (!reason.trim()) { setSaveError("A reason is required for the audit trail."); return; }
    setSaving(true);
    setSaveError(null);
    try {
      await apiFetch("/api/admin/subscription", token, {
        method: "PATCH",
        body: JSON.stringify({ ownerId, plan, status, reason: reason.trim() }),
      });
      setReason("");
      await load();
      onChanged();
    } catch (e) {
      setSaveError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  if (error) return <p className="text-sm text-red-400">{error}</p>;
  if (!detail) return <p className="font-mono text-sm text-cybermuted">// loading…</p>;

  const { user, subscription, scans, scanCount, usage } = detail;

  return (
    <div className="space-y-6">
      <button onClick={onClose} className="font-mono text-xs text-cybertext/50 hover:text-neon transition-colors">
        ← Back to customers
      </button>

      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
        <h3 className="font-mono text-xs uppercase tracking-wide text-cybermuted">// profile</h3>
        <p className="mt-2 text-sm text-cybertext">
          <span className="font-mono text-neon">{user.email}</span>
          {user.is_admin && <span className="ml-1 rounded bg-neon/10 px-1 text-[10px] text-neon">admin</span>}
        </p>
        <p className="text-sm text-cybertext/60">{user.company_name ?? "No company set"}</p>
        <p className="mt-1 text-xs text-cybermuted">Joined {reltime(user.created_at)} · {scanCount} total scans</p>
      </div>

      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
        <h3 className="font-mono text-xs uppercase tracking-wide text-cybermuted">// subscription</h3>
        <div className="mt-2 flex items-center gap-3 text-sm">
          <span className="capitalize text-cybertext/80">{subscription?.plan ?? "none"}</span>
          {subscription?.status && statusBadge(subscription.status)}
          {subscription?.source === "admin" && (
            <span className="rounded bg-amber-400/10 px-1 text-[10px] text-amber-400">manually granted</span>
          )}
        </div>
        {subscription?.grant_reason && (
          <p className="mt-1 text-xs text-cybermuted">Reason on file: {subscription.grant_reason}</p>
        )}
        {subscription?.stripe_customer_id && (
          <p className="mt-1 font-mono text-xs text-cybermuted">Stripe: {subscription.stripe_customer_id}</p>
        )}

        <div className="mt-4 space-y-3 border-t border-cyberborder/50 pt-4">
          <p className="text-xs text-cybertext/50">
            Override this customer&apos;s plan without Stripe (comps, pilots, support goodwill). A real Stripe
            checkout later always takes precedence over a manual grant.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <AdminSelect value={plan} onChange={(e) => setPlan(e.target.value)}>
              {PLAN_OPTIONS.map((p) => <option key={p} value={p}>{p}</option>)}
            </AdminSelect>
            <AdminSelect value={status} onChange={(e) => setStatus(e.target.value)}>
              {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s}</option>)}
            </AdminSelect>
            <AdminInput
              placeholder="Reason (required, kept in the audit log)"
              className="min-w-64 flex-1"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
            <button
              onClick={overridePlan}
              disabled={saving}
              className="rounded bg-neon/10 px-3 py-2 text-xs text-neon hover:bg-neon/20 disabled:opacity-40 transition-colors"
            >
              {saving ? "Saving…" : "Apply override"}
            </button>
          </div>
          {saveError && <p className="text-xs text-red-400">{saveError}</p>}
        </div>
      </div>

      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
        <h3 className="mb-2 font-mono text-xs uppercase tracking-wide text-cybermuted">// usage vs plan limits</h3>
        <div className="space-y-1">
          <UsageRow label="Monitored sites" count={usage.monitoredTargets.count} cap={usage.monitoredTargets.cap} />
          {usage.teamMembers && <UsageRow label="Team members" count={usage.teamMembers.count} cap={usage.teamMembers.cap} />}
          {usage.freeScans && (
            <UsageRow label="Free-tier scans (no active plan)" count={usage.freeScans.count} cap={usage.freeScans.allowed} />
          )}
        </div>
      </div>

      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
        <h3 className="mb-3 font-mono text-xs uppercase tracking-wide text-cybermuted">// recent scans</h3>
        {scans.length === 0 ? (
          <p className="text-sm text-cybermuted">No scans yet</p>
        ) : (
          <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-cyberborder text-left text-xs text-cybermuted">
                <th className="pb-2 pr-4">Target</th>
                <th className="pb-2 pr-4">Status</th>
                <th className="pb-2 pr-4">Score</th>
                <th className="pb-2">Created</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id} className="border-b border-cyberborder/50">
                  <td className="py-1.5 pr-4 max-w-48 truncate font-mono text-xs">
                    <a href={`/dashboard/scans/${s.id}`} className="text-neon hover:underline">{s.targetUrl}</a>
                  </td>
                  <td className="py-1.5 pr-4">{statusBadge(s.status)}</td>
                  <td className="py-1.5 pr-4 font-mono text-xs">{s.score ?? "—"}</td>
                  <td className="py-1.5 text-xs text-cybermuted">{reltime(s.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </div>
    </div>
  );
}

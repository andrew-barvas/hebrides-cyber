"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { getSession } from "@/lib/auth";
import { useSessionToken } from "@/lib/useSessionToken";
import { teamSizeLabel, budgetRangeLabel } from "@/lib/contactOptions";

// ─── Types ────────────────────────────────────────────────────────────────────

type Metrics = {
  totalCustomers: number;
  activeSubscriptions: number;
  totalScans: number;
  scansLast30d: number;
  scansByStatus: Record<string, number>;
  planBreakdown: { plan: string; count: number }[];
  mrrUsd: number;
  recentSignups: { id: string; email: string; company_name: string | null; created_at: string }[];
};

type Customer = {
  id: string;
  email: string;
  company_name: string | null;
  is_admin: boolean;
  plan: string | null;
  subscription_status: string | null;
  scan_count: number;
  created_at: string;
};

type ScanRow = {
  id: string;
  ownerEmail: string;
  ownerCompany: string | null;
  targetUrl: string;
  status: string;
  score: number | null;
  summary: string | null;
  jobId: string | null;
  createdAt: string;
};

type QueueData = {
  configured: boolean;
  note?: string;
  stats?: { waiting: number; active: number; completed: number; failed: number; delayed: number };
  jobs?: {
    active: QueueJob[];
    waiting: QueueJob[];
    failed: QueueJob[];
    completed: QueueJob[];
  };
};

type QueueJob = {
  id: string;
  scanId: string;
  targetUrl: string;
  addedAt: number;
  startedAt: number | null;
  finishedAt: number | null;
  progress: number;
};

type BlogPost = {
  id: string;
  slug: string;
  title: string;
  excerpt: string;
  status: "draft" | "published";
  published_at: string | null;
  updated_at: string;
  tags: string[];
  cover_image_url: string | null;
};

type BlogPostFull = BlogPost & {
  body: string;
  author_id: string;
  meta_description: string | null;
  og_image: string | null;
};

type AuditLog = {
  id: string;
  actor_email: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  created_at: string;
};

type Tab = "overview" | "customers" | "scans" | "queue" | "blog" | "audit" | "contacts";

type ContactEnquiry = {
  id: string;
  name: string;
  email: string;
  url: string | null;
  message: string;
  company: string | null;
  team_size: string | null;
  budget_range: string | null;
  read: boolean;
  created_at: string;
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function statusBadge(status: string) {
  const map: Record<string, string> = {
    completed: "bg-neon/20 text-neon",
    running:   "bg-seafoam/20 text-seafoam",
    pending:   "bg-amber-400/20 text-amber-400",
    failed:    "bg-red-400/20 text-red-400",
    published: "bg-neon/20 text-neon",
    draft:     "bg-cyberborder text-cybertext/60",
    active:    "bg-seafoam/20 text-seafoam",
    waiting:   "bg-amber-400/20 text-amber-400",
  };
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${map[status] ?? "bg-cyberborder text-cybertext/60"}`}>
      {status}
    </span>
  );
}

function reltime(ts: string | number) {
  const ms = typeof ts === "number" ? ts : new Date(ts).getTime();
  const diff = Date.now() - ms;
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)}h ago`;
  return `${Math.round(diff / 86_400_000)}d ago`;
}

async function apiFetch<T>(path: string, token: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...opts,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

// ─── Shared UI atoms ─────────────────────────────────────────────────────────

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <p className="text-2xl font-bold text-neon">{value}</p>
      <p className="mt-0.5 text-sm font-medium text-cybertext/70">{label}</p>
      {sub && <p className="mt-1 text-xs text-cybertext/40">{sub}</p>}
    </div>
  );
}

function AdminInput({ className = "", ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={`rounded-lg border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors ${className}`}
      {...props}
    />
  );
}

function AdminTextarea({ className = "", ...props }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={`rounded-lg border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors ${className}`}
      {...props}
    />
  );
}

function AdminSelect({ className = "", ...props }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={`rounded-lg border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext focus:border-neon focus:outline-none transition-colors ${className}`}
      {...props}
    />
  );
}

// ─── Overview Tab ────────────────────────────────────────────────────────────

function OverviewTab({ token }: { token: string }) {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<Metrics>("/api/admin/metrics", token)
      .then(setMetrics)
      .catch((e) => setErr(e.message));
  }, [token]);

  if (err) return <p className="text-red-400 text-sm">{err}</p>;
  if (!metrics) return <p className="text-cybertext/40 text-sm font-mono">// loading…</p>;

  return (
    <div className="space-y-8">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Customers" value={metrics.totalCustomers} />
        <StatCard label="Active subscriptions" value={metrics.activeSubscriptions} />
        <StatCard label="Total scans" value={metrics.totalScans} sub={`${metrics.scansLast30d} last 30 days`} />
        {/* mrrUsd is a legacy field name from before pricing was set in
            GBP — the API's real prices (£20/£35/£75, see admin/metrics.ts)
            were already correct; this caption was the one place still
            showing the old $19/$49/$99 figures and the wrong currency
            symbol, silently contradicting its own API response. */}
        <StatCard label="Est. MRR" value={`£${metrics.mrrUsd.toLocaleString()}`} sub="basic £20 · pro £35 · agency £75" />
      </div>

      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
        <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
          <h3 className="mb-3 font-mono text-xs text-cybertext/40 uppercase tracking-wide">// plans</h3>
          <div className="space-y-2">
            {metrics.planBreakdown.map((p) => (
              <div key={p.plan} className="flex items-center justify-between">
                <span className="capitalize text-sm text-cybertext/70">{p.plan}</span>
                <span className="text-sm font-medium text-neon">{p.count}</span>
              </div>
            ))}
            {metrics.planBreakdown.length === 0 && (
              <p className="text-xs text-cybertext/30">No active subscriptions</p>
            )}
          </div>
        </div>

        <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
          <h3 className="mb-3 font-mono text-xs text-cybertext/40 uppercase tracking-wide">// scan status</h3>
          <div className="space-y-2">
            {Object.entries(metrics.scansByStatus).map(([status, count]) => (
              <div key={status} className="flex items-center justify-between">
                {statusBadge(status)}
                <span className="text-sm font-medium text-neon">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
        <h3 className="mb-3 font-mono text-xs text-cybertext/40 uppercase tracking-wide">// recent signups</h3>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-cyberborder text-left text-xs text-cybertext/40">
              <th className="pb-2 pr-4">Email</th>
              <th className="pb-2 pr-4">Company</th>
              <th className="pb-2">Joined</th>
            </tr>
          </thead>
          <tbody>
            {metrics.recentSignups.map((u) => (
              <tr key={u.id} className="border-b border-cyberborder/50">
                <td className="py-1.5 pr-4 font-mono text-xs text-cybertext">{u.email}</td>
                <td className="py-1.5 pr-4 text-cybertext/50">{u.company_name ?? "—"}</td>
                <td className="py-1.5 text-cybertext/40">{reltime(u.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Customers Tab ────────────────────────────────────────────────────────────

function CustomersTab({ token }: { token: string }) {
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
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
        <span className="font-mono text-xs text-cybertext/40">{total} customers</span>
      </div>

      <div className="overflow-x-auto rounded-xl border border-cyberborder bg-cyberpanel">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-cyberborder bg-cyberbg text-left text-xs text-cybertext/40">
              <th className="px-4 py-3">Email</th>
              <th className="px-4 py-3">Company</th>
              <th className="px-4 py-3">Plan</th>
              <th className="px-4 py-3">Sub status</th>
              <th className="px-4 py-3">Scans</th>
              <th className="px-4 py-3">Joined</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center font-mono text-sm text-cybertext/30">// loading…</td></tr>
            ) : customers.length === 0 ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-sm text-cybertext/30">No customers found</td></tr>
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
                  <td className="px-4 py-2.5 capitalize text-cybertext/70">{c.plan ?? "none"}</td>
                  <td className="px-4 py-2.5">{c.subscription_status ? statusBadge(c.subscription_status) : "—"}</td>
                  <td className="px-4 py-2.5 text-cybertext/70">{c.scan_count}</td>
                  <td className="px-4 py-2.5 text-cybertext/40">{reltime(c.created_at)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {total > PAGE_SIZE && (
        <div className="flex justify-end gap-2">
          <button disabled={page === 1} onClick={() => setPage((p) => p - 1)} className="rounded border border-cyberborder px-3 py-1 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-30 transition-colors">← Prev</button>
          <span className="px-2 py-1 font-mono text-xs text-cybertext/40">Page {page}</span>
          <button disabled={page * PAGE_SIZE >= total} onClick={() => setPage((p) => p + 1)} className="rounded border border-cyberborder px-3 py-1 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-30 transition-colors">Next →</button>
        </div>
      )}
    </div>
  );
}

// ─── Scans Tab ────────────────────────────────────────────────────────────────

function ScansTab({ token }: { token: string }) {
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
            <tr className="border-b border-cyberborder bg-cyberbg text-left text-xs text-cybertext/40">
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
              <tr><td colSpan={6} className="px-4 py-8 text-center font-mono text-sm text-cybertext/30">// loading…</td></tr>
            ) : scans.length === 0 ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-sm text-cybertext/30">No scans found</td></tr>
            ) : (
              scans.map((s) => (
                <tr key={s.id} className="border-b border-cyberborder/50 hover:bg-cybertext/5 transition-colors">
                  <td className="px-4 py-2.5 font-mono text-xs max-w-48 truncate">
                    <a href={`/dashboard/scans/${s.id}`} className="text-neon hover:underline">{s.targetUrl}</a>
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
                  <td className="px-4 py-2.5 text-xs text-cybertext/40">{reltime(s.createdAt)}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex gap-1">
                      {(s.status === "running" || s.status === "pending") && (
                        <button onClick={() => action(s.id, "cancel")} className="rounded bg-red-400/10 px-2 py-0.5 text-xs text-red-400 hover:bg-red-400/20 transition-colors">
                          Cancel
                        </button>
                      )}
                      {s.status === "failed" && (
                        <button onClick={() => action(s.id, "retry")} className="rounded bg-seafoam/10 px-2 py-0.5 text-xs text-seafoam hover:bg-seafoam/20 transition-colors">
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
        <button disabled={page === 1} onClick={() => setPage((p) => p - 1)} className="rounded border border-cyberborder px-3 py-1 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-30 transition-colors">← Prev</button>
        <span className="px-2 py-1 font-mono text-xs text-cybertext/40">Page {page}</span>
        <button disabled={scans.length < PAGE_SIZE} onClick={() => setPage((p) => p + 1)} className="rounded border border-cyberborder px-3 py-1 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-30 transition-colors">Next →</button>
      </div>
    </div>
  );
}

// ─── Queue Tab ────────────────────────────────────────────────────────────────

function QueueTab({ token }: { token: string }) {
  const [data, setData] = useState<QueueData | null>(null);

  const load = useCallback(() => {
    apiFetch<QueueData>("/api/admin/queue", token).then(setData).catch(() => {});
  }, [token]);

  useEffect(() => {
    load();
    const iv = setInterval(load, 5_000);
    return () => clearInterval(iv);
  }, [load]);

  if (!data) return <p className="font-mono text-sm text-cybertext/30">// loading…</p>;

  if (!data.configured) {
    return (
      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-6">
        <p className="font-semibold text-cybertext/80">Queue data unavailable</p>
        <p className="mt-1 text-sm text-cybertext/50">{data.note ?? "Could not load scan_jobs."}</p>
      </div>
    );
  }

  const { stats, jobs } = data;

  return (
    <div className="space-y-6">
      <p className="font-mono text-xs text-cybertext/30">// auto-refreshes every 5 s</p>

      {stats && (
        <div className="grid grid-cols-5 gap-3">
          {(["active", "waiting", "delayed", "completed", "failed"] as const).map((k) => (
            <StatCard key={k} label={k} value={stats[k]} />
          ))}
        </div>
      )}

      {jobs && (
        <div className="space-y-4">
          {(["active", "waiting", "failed"] as const).map((state) => {
            const list = jobs[state] ?? [];
            if (list.length === 0) return null;
            return (
              <div key={state} className="rounded-xl border border-cyberborder bg-cyberpanel overflow-hidden">
                <div className="border-b border-cyberborder bg-cyberbg px-4 py-2.5 font-mono text-xs text-cybertext/40 uppercase tracking-wide">
                  {state} ({list.length})
                </div>
                {list.map((j) => (
                  <div key={j.id} className="flex items-center gap-4 border-b border-cyberborder/40 px-4 py-3 last:border-0">
                    <div className="flex-1 min-w-0">
                      <p className="truncate font-mono text-xs text-neon">{j.targetUrl}</p>
                      <p className="text-xs text-cybertext/40">scan: {j.scanId?.slice(0, 8)}…</p>
                    </div>
                    {state === "active" && (
                      <div className="w-24">
                        <div className="h-1.5 rounded-full bg-cyberborder">
                          <div
                            className="h-1.5 rounded-full bg-neon transition-all shadow-glowsm"
                            style={{ width: `${j.progress ?? 0}%` }}
                          />
                        </div>
                        <p className="mt-0.5 text-right font-mono text-xs text-cybertext/40">{j.progress ?? 0}%</p>
                      </div>
                    )}
                    <p className="text-xs text-cybertext/30 whitespace-nowrap">
                      {j.addedAt ? reltime(j.addedAt) : ""}
                    </p>
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Blog / CMS Tab ───────────────────────────────────────────────────────────

function BlogTab({ token }: { token: string }) {
  const [posts, setPosts] = useState<BlogPost[]>([]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [editing, setEditing] = useState<BlogPostFull | null>(null);
  const [creating, setCreating] = useState(false);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams();
    if (search) params.set("search", search);
    if (statusFilter) params.set("status", statusFilter);
    apiFetch<{ posts: BlogPost[] }>(`/api/admin/blog?${params}`, token)
      .then((d) => setPosts(d.posts))
      .finally(() => setLoading(false));
  }, [token, search, statusFilter]);

  useEffect(() => { load(); }, [load]);

  const openPost = async (slug: string) => {
    const post = await apiFetch<BlogPostFull>(`/api/admin/blog/${slug}`, token);
    setEditing(post);
  };

  const deletePost = async (slug: string) => {
    if (!confirm("Delete this post permanently?")) return;
    await apiFetch(`/api/admin/blog/${slug}`, token, { method: "DELETE" });
    load();
  };

  if (editing || creating) {
    return (
      <BlogEditor
        token={token}
        post={editing ?? undefined}
        onSave={() => { setEditing(null); setCreating(false); load(); }}
        onCancel={() => { setEditing(null); setCreating(false); }}
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <AdminInput
          type="search"
          placeholder="Search posts…"
          className="flex-1 min-w-40"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <AdminSelect
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="">All</option>
          <option value="draft">Drafts</option>
          <option value="published">Published</option>
        </AdminSelect>
        <button
          onClick={() => setCreating(true)}
          className="rounded-lg bg-neon px-4 py-2 text-sm font-medium text-cyberbg hover:opacity-90 transition-opacity shadow-glowsm"
        >
          + New post
        </button>
      </div>

      {loading ? (
        <p className="font-mono text-sm text-cybertext/30">// loading…</p>
      ) : posts.length === 0 ? (
        <p className="font-mono text-sm text-cybertext/30">// no posts found</p>
      ) : (
        <div className="rounded-xl border border-cyberborder bg-cyberpanel overflow-hidden">
          {posts.map((p) => (
            <div key={p.id} className="flex items-start gap-4 border-b border-cyberborder/50 px-4 py-4 last:border-0 hover:bg-cybertext/5 transition-colors">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <p className="font-medium text-cybertext">{p.title}</p>
                  {statusBadge(p.status)}
                </div>
                <p className="mt-0.5 text-xs text-cybertext/40 truncate">{p.excerpt || "No excerpt"}</p>
                <div className="mt-1 flex items-center gap-2 font-mono text-xs text-cybertext/30">
                  <span>/{p.slug}</span>
                  <span>·</span>
                  <span>Updated {reltime(p.updated_at)}</span>
                  {p.tags.length > 0 && (
                    <>
                      <span>·</span>
                      {p.tags.slice(0, 3).map((t) => (
                        <span key={t} className="rounded border border-cyberborder px-1.5 py-0.5 text-neon/60">{t}</span>
                      ))}
                    </>
                  )}
                </div>
              </div>
              <div className="flex shrink-0 gap-1">
                <button onClick={() => openPost(p.slug)} className="rounded border border-cyberborder px-2.5 py-1 text-xs text-cybertext/70 hover:border-neon hover:text-neon transition-colors">Edit</button>
                <button onClick={() => deletePost(p.slug)} className="rounded bg-red-400/10 px-2.5 py-1 text-xs text-red-400 hover:bg-red-400/20 transition-colors">Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function BlogEditor({
  token, post, onSave, onCancel,
}: {
  token: string;
  post?: BlogPostFull;
  onSave: () => void;
  onCancel: () => void;
}) {
  const [title, setTitle] = useState(post?.title ?? "");
  const [slug, setSlug] = useState(post?.slug ?? "");
  const [excerpt, setExcerpt] = useState(post?.excerpt ?? "");
  const [body, setBody] = useState(post?.body ?? "");
  const [tags, setTags] = useState((post?.tags ?? []).join(", "));
  const [status, setStatus] = useState<"draft" | "published">(post?.status ?? "draft");
  const [coverImageUrl, setCoverImageUrl] = useState(post?.cover_image_url ?? "");
  const [metaDescription, setMetaDescription] = useState(post?.meta_description ?? "");
  const [ogImage, setOgImage] = useState(post?.og_image ?? "");
  const [saving, setSaving] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [slugError, setSlugError] = useState<string | null>(null);
  const [preview, setPreview] = useState(false);
  const [showSeo, setShowSeo] = useState(false);
  const [isDirty, setIsDirty] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const autoSlug = (t: string) =>
    t.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

  const wordCount = body.trim().split(/\s+/).filter(Boolean).length;
  const readMins = Math.max(1, Math.round(wordCount / 200));

  useEffect(() => {
    const handler = (e: BeforeUnloadEvent) => {
      if (isDirty) { e.preventDefault(); e.returnValue = ""; }
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [isDirty]);

  const markDirty = () => setIsDirty(true);

  useEffect(() => {
    if (!slug || (post && slug === post.slug)) { setSlugError(null); return; }
    const t = setTimeout(async () => {
      try {
        const res = await fetch(`/api/admin/blog/${slug}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) setSlugError(`Slug "${slug}" is already taken.`);
        else setSlugError(null);
      } catch { setSlugError(null); }
    }, 600);
    return () => clearTimeout(t);
  }, [slug, post, token]);

  async function uploadImage(file: File) {
    setUploading(true);
    try {
      const reader = new FileReader();
      const dataUrl = await new Promise<string>((resolve, reject) => {
        reader.onload = () => resolve(reader.result as string);
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });
      const res = await apiFetch<{ url: string }>("/api/admin/blog/upload-image", token, {
        method: "POST",
        body: JSON.stringify({ dataUrl, filename: file.name }),
      });
      setCoverImageUrl(res.url);
      markDirty();
    } catch (e) {
      setError(`Image upload failed: ${(e as Error).message}`);
    } finally {
      setUploading(false);
    }
  }

  const save = async () => {
    if (slugError) { setError("Fix the slug conflict before saving."); return; }
    setSaving(true);
    setError(null);
    try {
      const payload = {
        title, slug, excerpt, body,
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
        status,
        cover_image_url: coverImageUrl || null,
        meta_description: metaDescription || null,
        og_image: ogImage || null,
      };
      if (post) {
        await apiFetch(`/api/admin/blog/${post.slug}`, token, { method: "PATCH", body: JSON.stringify(payload) });
      } else {
        await apiFetch("/api/admin/blog", token, { method: "POST", body: JSON.stringify(payload) });
      }
      setIsDirty(false);
      onSave();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={() => { if (!isDirty || confirm("Discard unsaved changes?")) onCancel(); }}
          className="font-mono text-sm text-cybertext/50 hover:text-neon transition-colors"
        >
          ← back
        </button>
        <h2 className="text-lg font-semibold text-cybertext">{post ? "Edit post" : "New post"}</h2>
        {isDirty && <span className="font-mono text-xs text-amber-400">// unsaved changes</span>}
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-cybertext/30">{wordCount} words · {readMins} min read</span>
          <button
            onClick={() => setShowSeo((v) => !v)}
            className="rounded border border-cyberborder px-3 py-1.5 text-xs text-cybertext/60 hover:border-neon hover:text-neon transition-colors"
          >
            SEO {showSeo ? "▲" : "▼"}
          </button>
          <button
            onClick={() => setPreview((v) => !v)}
            className="rounded border border-cyberborder px-3 py-1.5 text-sm text-cybertext/60 hover:border-neon hover:text-neon transition-colors"
          >
            {preview ? "Edit" : "Preview"}
          </button>
          <AdminSelect
            value={status}
            onChange={(e) => { setStatus(e.target.value as "draft" | "published"); markDirty(); }}
          >
            <option value="draft">Draft</option>
            <option value="published">Publish</option>
          </AdminSelect>
          <button
            onClick={save}
            disabled={saving || !!slugError}
            className="rounded-lg bg-neon px-4 py-1.5 text-sm font-medium text-cyberbg hover:opacity-90 disabled:opacity-50 shadow-glowsm transition-opacity"
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>

      {error && (
        <p className="rounded border border-red-400/30 bg-red-400/10 px-3 py-2 text-sm text-red-400">{error}</p>
      )}

      {/* SEO panel */}
      {showSeo && (
        <div className="rounded-xl border border-cyberborder bg-cyberpanel p-4 space-y-3">
          <h3 className="font-mono text-xs text-cybertext/40 uppercase tracking-wide">// SEO & Open Graph</h3>
          <div>
            <label className="mb-1 block font-mono text-xs text-cybertext/40">Meta description (155 chars max)</label>
            <AdminTextarea
              value={metaDescription}
              onChange={(e) => { setMetaDescription(e.target.value); markDirty(); }}
              rows={2}
              maxLength={155}
              placeholder="Override the excerpt for search engines…"
              className="w-full"
            />
            <p className="text-right font-mono text-xs text-cybertext/30">{metaDescription.length}/155</p>
          </div>
          <div>
            <label className="mb-1 block font-mono text-xs text-cybertext/40">OG image URL (overrides cover image for social sharing)</label>
            <AdminInput
              type="url"
              value={ogImage}
              onChange={(e) => { setOgImage(e.target.value); markDirty(); }}
              placeholder="https://…"
              className="w-full"
            />
          </div>
        </div>
      )}

      {preview ? (
        <div className="prose prose-sm prose-invert max-w-none rounded-xl border border-cyberborder bg-cyberpanel p-6 prose-headings:text-neon prose-a:text-neon prose-code:bg-cyberbg prose-code:text-neon">
          {coverImageUrl && <img src={coverImageUrl} alt="" className="mb-6 w-full rounded-lg object-cover max-h-56" />}
          <h1>{title || "Untitled"}</h1>
          <p className="lead text-cybertext/60">{excerpt}</p>
          <div style={{ whiteSpace: "pre-wrap" }}>{body}</div>
        </div>
      ) : (
        <div className="grid gap-3">
          <AdminInput
            type="text"
            placeholder="Post title"
            value={title}
            onChange={(e) => {
              setTitle(e.target.value);
              if (!post) setSlug(autoSlug(e.target.value));
              markDirty();
            }}
            className="w-full text-lg font-semibold"
          />

          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-cybertext/40 shrink-0">Slug:</span>
            <input
              type="text"
              value={slug}
              onChange={(e) => { setSlug(e.target.value.toLowerCase().replace(/\s/g, "-")); markDirty(); }}
              className={`flex-1 rounded border bg-cyberbg px-2 py-1 font-mono text-xs text-cybertext focus:outline-none transition-colors ${
                slugError ? "border-red-400 focus:border-red-400" : "border-cyberborder focus:border-neon"
              }`}
            />
            {slugError && <span className="text-xs text-red-400">{slugError}</span>}
          </div>

          {/* Cover image */}
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="font-mono text-xs text-cybertext/40">Cover image</span>
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading}
                className="rounded border border-cyberborder px-2 py-0.5 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-50 transition-colors"
              >
                {uploading ? "Uploading…" : "Upload"}
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                className="hidden"
                onChange={(e) => { const f = e.target.files?.[0]; if (f) uploadImage(f); }}
              />
            </div>
            {coverImageUrl ? (
              <div className="relative inline-block">
                <img src={coverImageUrl} alt="Cover" className="h-24 rounded-lg object-cover border border-cyberborder" />
                <button
                  onClick={() => { setCoverImageUrl(""); markDirty(); }}
                  className="absolute -right-2 -top-2 rounded-full bg-cyberpanel border border-cyberborder px-1.5 py-0.5 text-xs text-red-400 hover:text-red-300"
                >
                  ✕
                </button>
              </div>
            ) : (
              <AdminInput
                type="url"
                placeholder="Or paste a URL…"
                value={coverImageUrl}
                onChange={(e) => { setCoverImageUrl(e.target.value); markDirty(); }}
                className="w-full"
              />
            )}
          </div>

          <AdminTextarea
            placeholder="Short excerpt (shown on listing page)…"
            value={excerpt}
            onChange={(e) => { setExcerpt(e.target.value); markDirty(); }}
            rows={2}
            className="w-full resize-y"
          />

          <AdminTextarea
            placeholder="Post body (Markdown supported)…"
            value={body}
            onChange={(e) => { setBody(e.target.value); markDirty(); }}
            rows={22}
            className="w-full resize-y font-mono"
          />

          <AdminInput
            type="text"
            placeholder="Tags (comma-separated: security, tls, headers)"
            value={tags}
            onChange={(e) => { setTags(e.target.value); markDirty(); }}
            className="w-full"
          />
        </div>
      )}
    </div>
  );
}

// ─── Audit Log Tab ────────────────────────────────────────────────────────────

function AuditTab({ token }: { token: string }) {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [search, setSearch] = useState("");
  const [actor, setActor] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const PAGE_SIZE = 50;

  const load = useCallback(async (q: string, a: string, p: number) => {
    const params = new URLSearchParams({ page: String(p) });
    if (q) params.set("search", q);
    if (a) params.set("actor", a);
    apiFetch<{ logs: AuditLog[]; total: number }>(`/api/admin/audit?${params}`, token)
      .then((d) => { setLogs(d.logs); setTotal(d.total); })
      .catch(() => {});
  }, [token]);

  useEffect(() => { load(search, actor, page); }, [search, actor, page, load]);

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
        <span className="font-mono text-xs text-cybertext/40">{total} events</span>
      </div>

      <div className="overflow-x-auto rounded-xl border border-cyberborder bg-cyberpanel">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-cyberborder bg-cyberbg text-left text-xs text-cybertext/40">
              <th className="px-4 py-3">When</th>
              <th className="px-4 py-3">Actor</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Resource</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 ? (
              <tr><td colSpan={4} className="px-4 py-8 text-center font-mono text-sm text-cybertext/30">// no audit events found</td></tr>
            ) : (
              logs.map((l) => (
                <tr key={l.id} className="border-b border-cyberborder/50 hover:bg-cybertext/5 transition-colors">
                  <td className="px-4 py-2 font-mono text-xs text-cybertext/40 whitespace-nowrap">{reltime(l.created_at)}</td>
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
          <button disabled={page === 1} onClick={() => setPage((p) => p - 1)} className="rounded border border-cyberborder px-3 py-1 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-30 transition-colors">← Prev</button>
          <span className="px-2 py-1 font-mono text-xs text-cybertext/40">Page {page}</span>
          <button disabled={page * PAGE_SIZE >= total} onClick={() => setPage((p) => p + 1)} className="rounded border border-cyberborder px-3 py-1 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-30 transition-colors">Next →</button>
        </div>
      )}
    </div>
  );
}

// ─── Contacts Tab ────────────────────────────────────────────────────────────

function ContactsTab({ token }: { token: string }) {
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

  if (loading) return <p className="text-cybertext/40 text-sm font-mono">// loading…</p>;
  if (err) return <p className="text-red-400 text-sm">{err}</p>;
  if (total === 0)
    return (
      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-8 text-center">
        <p className="text-cybertext/40 text-sm">No contact enquiries yet.</p>
      </div>
    );

  const unread = enquiries.filter((e) => !e.read).length;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <p className="font-mono text-xs text-cybertext/40">{total} enquiries</p>
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
                  <span className="font-mono text-xs text-cybertext/40">{e.email}</span>
                </div>
                <p className="mt-1 text-xs text-cybertext/50 truncate max-w-lg">{e.message}</p>
              </div>
              <div className="flex-shrink-0 text-right">
                <p className="text-xs text-cybertext/30">{reltime(e.created_at)}</p>
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
          <span className="px-2 py-1 font-mono text-xs text-cybertext/40">Page {page}</span>
          <button disabled={page * PAGE_SIZE >= total} onClick={() => setPage((p) => p + 1)} className="rounded border border-cyberborder px-3 py-1 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-30 transition-colors">Next →</button>
        </div>
      )}
    </div>
  );
}

// ─── Root Page ────────────────────────────────────────────────────────────────

export default function AdminPage() {
  const [authState, setAuthState] = useState<"loading" | "signed-out" | "unauthorized" | "ready">("loading");
  const [activeTab, setActiveTab] = useState<Tab>("overview");
  // Every tab below sends this as a bearer token. Held in a hook that tracks
  // onAuthStateChange rather than captured once from the mount-time session —
  // an admin leaving this page open past the one-hour token lifetime would
  // otherwise find every tab's requests failing with 401 while the page still
  // looked signed in.
  const token = useSessionToken();

  useEffect(() => {
    (async () => {
      const s = await getSession();
      if (!s) { setAuthState("signed-out"); return; }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      let res: Response;
      try {
        res = await fetch("/api/admin/metrics", {
          signal: controller.signal,
          headers: { Authorization: `Bearer ${s.access_token}` },
        });
      } catch {
        setAuthState("unauthorized");
        return;
      } finally {
        clearTimeout(timeout);
      }

      if (res.status === 403 || !res.ok) { setAuthState("unauthorized"); return; }

      setAuthState("ready");
    })().catch(() => setAuthState("unauthorized"));
  }, []);

  if (authState === "loading") {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center">
        <p className="font-mono text-sm text-cybertext/30">// authenticating…</p>
      </div>
    );
  }

  if (authState === "signed-out") {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center px-6">
        <div className="text-center">
          <p className="mb-3 font-mono text-sm text-neon">// access denied</p>
          <h1 className="text-2xl font-bold text-cybertext">Sign in required</h1>
          <Link href="/login" className="mt-6 inline-block text-neon underline">Sign in →</Link>
        </div>
      </div>
    );
  }

  if (authState === "unauthorized") {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center px-6">
        <div className="max-w-md">
          <p className="mb-3 font-mono text-sm text-red-400">// 403 forbidden</p>
          <h1 className="text-2xl font-bold text-cybertext">Admin access required</h1>
          <div className="mt-4 space-y-2 text-sm text-cybertext/60">
            <p>Could not verify admin access. Common causes:</p>
            <ul className="list-disc pl-5 space-y-1 text-cybertext/50">
              <li>You&apos;re not signed in — <Link href="/login" className="text-neon underline">sign in first</Link></li>
              <li>Your account doesn&apos;t have <code className="font-mono bg-cyberpanel px-1 rounded text-neon">is_admin = true</code> in Supabase</li>
              <li><code className="font-mono bg-cyberpanel px-1 rounded text-neon">SUPABASE_SERVICE_ROLE_KEY</code> not set in Azure app settings</li>
              <li>API routes not deployed yet — wait for CI to finish</li>
            </ul>
          </div>
          <Link href="/dashboard" className="mt-6 inline-block text-neon underline">← Dashboard</Link>
        </div>
      </div>
    );
  }

  const tabs: { key: Tab; label: string }[] = [
    { key: "overview",  label: "Overview" },
    { key: "customers", label: "Customers" },
    { key: "scans",     label: "Scans" },
    { key: "queue",     label: "Queue" },
    { key: "blog",      label: "Blog / CMS" },
    { key: "audit",     label: "Audit log" },
    { key: "contacts",  label: "Contacts" },
  ];

  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      {/* Subtle grid overlay */}
      <div className="bg-grid pointer-events-none fixed inset-0 opacity-30" />

      <div className="relative mx-auto max-w-7xl px-4 py-8">
        {/* Header */}
        <div className="mb-6 flex items-baseline justify-between">
          <div>
            <p className="font-mono text-xs text-neon/50">$ sudo hebrides-cyber --admin</p>
            <h1 className="text-2xl font-bold text-cybertext">Admin</h1>
          </div>
          <Link href="/dashboard" className="font-mono text-sm text-cybertext/40 hover:text-neon transition-colors">← Dashboard</Link>
        </div>

        {/* Tabs */}
        <nav className="mb-6 flex gap-1 border-b border-cyberborder">
          {tabs.map((t) => (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key)}
              className={`px-4 py-2 text-sm font-medium transition-colors ${
                activeTab === t.key
                  ? "border-b-2 border-neon text-neon"
                  : "text-cybertext/40 hover:text-cybertext"
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>

        {/* Content */}
        {token && (
          <>
            {activeTab === "overview"  && <OverviewTab  token={token} />}
            {activeTab === "customers" && <CustomersTab token={token} />}
            {activeTab === "scans"     && <ScansTab     token={token} />}
            {activeTab === "queue"     && <QueueTab     token={token} />}
            {activeTab === "blog"      && <BlogTab      token={token} />}
            {activeTab === "audit"     && <AuditTab     token={token} />}
            {activeTab === "contacts"  && <ContactsTab  token={token} />}
          </>
        )}
      </div>
    </div>
  );
}

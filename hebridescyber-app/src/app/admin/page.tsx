"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { getSession } from "@/lib/auth";

// ─── Types ────────────────────────────────────────────────────────────────────

type Session = { access_token: string };

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

type Tab = "overview" | "customers" | "scans" | "queue" | "blog" | "audit";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function statusBadge(status: string) {
  const map: Record<string, string> = {
    completed: "bg-emerald-100 text-emerald-800",
    running: "bg-blue-100 text-blue-800",
    pending: "bg-amber-100 text-amber-800",
    failed: "bg-red-100 text-red-800",
    published: "bg-emerald-100 text-emerald-800",
    draft: "bg-slate-100 text-slate-700",
    active: "bg-blue-100 text-blue-800",
    waiting: "bg-amber-100 text-amber-800",
  };
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${map[status] ?? "bg-slate-100 text-slate-700"}`}>
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

// ─── Stat Card ───────────────────────────────────────────────────────────────

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-2xl font-bold text-atlantic">{value}</p>
      <p className="mt-0.5 text-sm font-medium text-slatedark/80">{label}</p>
      {sub && <p className="mt-1 text-xs text-slatedark/50">{sub}</p>}
    </div>
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

  if (err) return <p className="text-red-600 text-sm">{err}</p>;
  if (!metrics) return <p className="text-slatedark/50 text-sm">Loading…</p>;

  return (
    <div className="space-y-8">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Customers" value={metrics.totalCustomers} />
        <StatCard label="Active subscriptions" value={metrics.activeSubscriptions} />
        <StatCard label="Total scans" value={metrics.totalScans} sub={`${metrics.scansLast30d} last 30 days`} />
        <StatCard label="Est. MRR" value={`$${metrics.mrrUsd.toLocaleString()}`} sub="basic $19 · pro $49 · agency $99" />
      </div>

      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
        {/* Plan breakdown */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="mb-3 text-sm font-semibold text-slatedark/70 uppercase tracking-wide">Plans</h3>
          <div className="space-y-2">
            {metrics.planBreakdown.map((p) => (
              <div key={p.plan} className="flex items-center justify-between">
                <span className="capitalize text-sm text-slatedark">{p.plan}</span>
                <span className="text-sm font-medium text-atlantic">{p.count}</span>
              </div>
            ))}
            {metrics.planBreakdown.length === 0 && <p className="text-xs text-slatedark/40">No active subscriptions</p>}
          </div>
        </div>

        {/* Scan status breakdown */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h3 className="mb-3 text-sm font-semibold text-slatedark/70 uppercase tracking-wide">Scan status</h3>
          <div className="space-y-2">
            {Object.entries(metrics.scansByStatus).map(([status, count]) => (
              <div key={status} className="flex items-center justify-between">
                {statusBadge(status)}
                <span className="text-sm font-medium text-atlantic">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent signups */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h3 className="mb-3 text-sm font-semibold text-slatedark/70 uppercase tracking-wide">Recent signups</h3>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 text-left text-xs text-slatedark/50">
              <th className="pb-2 pr-4">Email</th>
              <th className="pb-2 pr-4">Company</th>
              <th className="pb-2">Joined</th>
            </tr>
          </thead>
          <tbody>
            {metrics.recentSignups.map((u) => (
              <tr key={u.id} className="border-b border-slate-50">
                <td className="py-1.5 pr-4 text-slatedark">{u.email}</td>
                <td className="py-1.5 pr-4 text-slatedark/60">{u.company_name ?? "—"}</td>
                <td className="py-1.5 text-slatedark/50">{reltime(u.created_at)}</td>
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

  const load = useCallback(
    async (q: string, p: number) => {
      setLoading(true);
      try {
        const params = new URLSearchParams({ page: String(p) });
        if (q) params.set("search", q);
        const data = await apiFetch<{ customers: Customer[]; total: number }>(
          `/api/admin/customers?${params}`,
          token
        );
        setCustomers(data.customers);
        setTotal(data.total);
      } catch {
        /* handled by loading state */
      } finally {
        setLoading(false);
      }
    },
    [token]
  );

  useEffect(() => { load(search, page); }, [search, page, load]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <input
          type="search"
          placeholder="Search by email or company…"
          className="flex-1 rounded-lg border border-slate-200 px-3 py-2 text-sm focus:border-atlantic focus:outline-none"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1); }}
        />
        <span className="text-xs text-slatedark/50">{total} customers</span>
      </div>

      <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 bg-slate-50 text-left text-xs text-slatedark/60">
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
              <tr><td colSpan={6} className="px-4 py-8 text-center text-slatedark/40">Loading…</td></tr>
            ) : customers.length === 0 ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-slatedark/40">No customers found</td></tr>
            ) : (
              customers.map((c) => (
                <tr key={c.id} className="border-b border-slate-50 hover:bg-slate-50/50">
                  <td className="px-4 py-2.5 text-atlantic font-mono text-xs">
                    {c.email}
                    {c.is_admin && (
                      <span className="ml-1 rounded bg-atlantic/10 px-1 text-[10px] text-atlantic">admin</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-slatedark/70">{c.company_name ?? "—"}</td>
                  <td className="px-4 py-2.5 capitalize">{c.plan ?? "none"}</td>
                  <td className="px-4 py-2.5">{c.subscription_status ? statusBadge(c.subscription_status) : "—"}</td>
                  <td className="px-4 py-2.5">{c.scan_count}</td>
                  <td className="px-4 py-2.5 text-slatedark/50">{reltime(c.created_at)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {total > PAGE_SIZE && (
        <div className="flex justify-end gap-2">
          <button disabled={page === 1} onClick={() => setPage((p) => p - 1)} className="rounded border px-3 py-1 text-xs disabled:opacity-40">← Prev</button>
          <span className="px-2 py-1 text-xs text-slatedark/50">Page {page}</span>
          <button disabled={page * PAGE_SIZE >= total} onClick={() => setPage((p) => p + 1)} className="rounded border px-3 py-1 text-xs disabled:opacity-40">Next →</button>
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
        <input
          type="search"
          placeholder="Filter by target URL…"
          className="flex-1 min-w-48 rounded-lg border border-slate-200 px-3 py-2 text-sm focus:border-atlantic focus:outline-none"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1); }}
        />
        <select
          className="rounded-lg border border-slate-200 px-3 py-2 text-sm focus:outline-none"
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
        >
          <option value="">All statuses</option>
          <option value="pending">Pending</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
        </select>
      </div>

      <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 bg-slate-50 text-left text-xs text-slatedark/60">
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
              <tr><td colSpan={6} className="px-4 py-8 text-center text-slatedark/40">Loading…</td></tr>
            ) : scans.length === 0 ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-slatedark/40">No scans found</td></tr>
            ) : (
              scans.map((s) => (
                <tr key={s.id} className="border-b border-slate-50 hover:bg-slate-50/50">
                  <td className="px-4 py-2.5 font-mono text-xs max-w-48 truncate text-atlantic">
                    <a href={`/dashboard/scans/${s.id}`} className="hover:underline">{s.targetUrl}</a>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-slatedark/70 max-w-36 truncate">{s.ownerEmail}</td>
                  <td className="px-4 py-2.5">{statusBadge(s.status)}</td>
                  <td className="px-4 py-2.5 text-sm font-medium">
                    {s.score !== null ? (
                      <span className={s.score >= 70 ? "text-emerald-600" : s.score >= 40 ? "text-amber-600" : "text-red-600"}>
                        {s.score}
                      </span>
                    ) : "—"}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-slatedark/50">{reltime(s.createdAt)}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex gap-1">
                      {(s.status === "running" || s.status === "pending") && (
                        <button onClick={() => action(s.id, "cancel")} className="rounded bg-red-50 px-2 py-0.5 text-xs text-red-700 hover:bg-red-100">
                          Cancel
                        </button>
                      )}
                      {s.status === "failed" && (
                        <button onClick={() => action(s.id, "retry")} className="rounded bg-blue-50 px-2 py-0.5 text-xs text-blue-700 hover:bg-blue-100">
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
        <button disabled={page === 1} onClick={() => setPage((p) => p - 1)} className="rounded border px-3 py-1 text-xs disabled:opacity-40">← Prev</button>
        <span className="px-2 py-1 text-xs text-slatedark/50">Page {page}</span>
        <button disabled={scans.length < PAGE_SIZE} onClick={() => setPage((p) => p + 1)} className="rounded border px-3 py-1 text-xs disabled:opacity-40">Next →</button>
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

  if (!data) return <p className="text-sm text-slatedark/40">Loading…</p>;

  if (!data.configured) {
    return (
      <div className="rounded-xl border border-amber-200 bg-amber-50 p-6 text-sm text-amber-800">
        <p className="font-semibold">Queue not configured</p>
        <p className="mt-1">{data.note}</p>
        <p className="mt-3 text-xs">Set <code className="font-mono bg-amber-100 px-1 rounded">REDIS_URL</code> and run <code className="font-mono bg-amber-100 px-1 rounded">docker compose up</code> to enable the async queue.</p>
      </div>
    );
  }

  const { stats, jobs } = data;

  return (
    <div className="space-y-6">
      <p className="text-xs text-slatedark/40">Auto-refreshes every 5 s</p>

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
              <div key={state} className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
                <div className="border-b border-slate-100 px-4 py-2.5 text-xs font-semibold text-slatedark/60 uppercase tracking-wide bg-slate-50">
                  {state} ({list.length})
                </div>
                {list.map((j) => (
                  <div key={j.id} className="flex items-center gap-4 border-b border-slate-50 px-4 py-3 last:border-0">
                    <div className="flex-1 min-w-0">
                      <p className="truncate font-mono text-xs text-atlantic">{j.targetUrl}</p>
                      <p className="text-xs text-slatedark/50">scan: {j.scanId?.slice(0, 8)}…</p>
                    </div>
                    {state === "active" && (
                      <div className="w-24">
                        <div className="h-1.5 rounded-full bg-slate-100">
                          <div
                            className="h-1.5 rounded-full bg-atlantic transition-all"
                            style={{ width: `${j.progress ?? 0}%` }}
                          />
                        </div>
                        <p className="mt-0.5 text-right text-xs text-slatedark/50">{j.progress ?? 0}%</p>
                      </div>
                    )}
                    <p className="text-xs text-slatedark/40 whitespace-nowrap">
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
        <input
          type="search"
          placeholder="Search posts…"
          className="flex-1 min-w-40 rounded-lg border border-slate-200 px-3 py-2 text-sm focus:outline-none focus:border-atlantic"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          className="rounded-lg border border-slate-200 px-3 py-2 text-sm focus:outline-none"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="">All</option>
          <option value="draft">Drafts</option>
          <option value="published">Published</option>
        </select>
        <button
          onClick={() => setCreating(true)}
          className="rounded-lg bg-atlantic px-4 py-2 text-sm font-medium text-white hover:opacity-90"
        >
          + New post
        </button>
      </div>

      {loading ? (
        <p className="text-sm text-slatedark/40">Loading…</p>
      ) : posts.length === 0 ? (
        <p className="text-sm text-slatedark/40">No posts found.</p>
      ) : (
        <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
          {posts.map((p) => (
            <div key={p.id} className="flex items-start gap-4 border-b border-slate-50 px-4 py-4 last:border-0 hover:bg-slate-50/50">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <p className="font-medium text-slatedark">{p.title}</p>
                  {statusBadge(p.status)}
                </div>
                <p className="mt-0.5 text-xs text-slatedark/50 truncate">{p.excerpt || "No excerpt"}</p>
                <div className="mt-1 flex items-center gap-2 text-xs text-slatedark/40">
                  <span>/{p.slug}</span>
                  <span>·</span>
                  <span>Updated {reltime(p.updated_at)}</span>
                  {p.tags.length > 0 && (
                    <>
                      <span>·</span>
                      {p.tags.slice(0, 3).map((t) => (
                        <span key={t} className="rounded bg-slate-100 px-1.5 py-0.5">{t}</span>
                      ))}
                    </>
                  )}
                </div>
              </div>
              <div className="flex shrink-0 gap-1">
                <button onClick={() => openPost(p.slug)} className="rounded bg-slate-100 px-2.5 py-1 text-xs hover:bg-slate-200">Edit</button>
                <button onClick={() => deletePost(p.slug)} className="rounded bg-red-50 px-2.5 py-1 text-xs text-red-700 hover:bg-red-100">Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function BlogEditor({
  token,
  post,
  onSave,
  onCancel,
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

  // Warn before navigating away with unsaved changes.
  useEffect(() => {
    const handler = (e: BeforeUnloadEvent) => {
      if (isDirty) { e.preventDefault(); e.returnValue = ""; }
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [isDirty]);

  const markDirty = () => setIsDirty(true);

  // Validate slug uniqueness (debounced) — skip check when editing the same post.
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
          className="text-sm text-slatedark/60 hover:text-slatedark"
        >
          ← Back
        </button>
        <h2 className="text-lg font-semibold text-atlantic">{post ? "Edit post" : "New post"}</h2>
        {isDirty && <span className="text-xs text-amber-600">Unsaved changes</span>}
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <span className="text-xs text-slatedark/40">{wordCount} words · {readMins} min read</span>
          <button onClick={() => setShowSeo((v) => !v)} className="rounded border border-slate-200 px-3 py-1.5 text-xs hover:bg-slate-50">
            SEO {showSeo ? "▲" : "▼"}
          </button>
          <button onClick={() => setPreview((v) => !v)} className="rounded border border-slate-200 px-3 py-1.5 text-sm hover:bg-slate-50">
            {preview ? "Edit" : "Preview"}
          </button>
          <select
            value={status}
            onChange={(e) => { setStatus(e.target.value as "draft" | "published"); markDirty(); }}
            className="rounded-lg border border-slate-200 px-2 py-1.5 text-sm"
          >
            <option value="draft">Draft</option>
            <option value="published">Publish</option>
          </select>
          <button
            onClick={save}
            disabled={saving || !!slugError}
            className="rounded-lg bg-atlantic px-4 py-1.5 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>

      {error && <p className="rounded bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}

      {/* SEO panel */}
      {showSeo && (
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 space-y-3">
          <h3 className="text-xs font-semibold text-slatedark/60 uppercase tracking-wide">SEO & Open Graph</h3>
          <div>
            <label className="mb-1 block text-xs text-slatedark/60">Meta description (155 chars max)</label>
            <textarea
              value={metaDescription}
              onChange={(e) => { setMetaDescription(e.target.value); markDirty(); }}
              rows={2}
              maxLength={155}
              placeholder="Override the excerpt for search engines…"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm focus:border-atlantic focus:outline-none"
            />
            <p className="text-right text-xs text-slatedark/40">{metaDescription.length}/155</p>
          </div>
          <div>
            <label className="mb-1 block text-xs text-slatedark/60">OG image URL (overrides cover image for social sharing)</label>
            <input
              type="url"
              value={ogImage}
              onChange={(e) => { setOgImage(e.target.value); markDirty(); }}
              placeholder="https://…"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm focus:border-atlantic focus:outline-none"
            />
          </div>
        </div>
      )}

      {preview ? (
        <div className="prose prose-sm max-w-none rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          {coverImageUrl && <img src={coverImageUrl} alt="" className="mb-6 w-full rounded-lg object-cover max-h-56" />}
          <h1>{title || "Untitled"}</h1>
          <p className="lead text-slatedark/70">{excerpt}</p>
          <div style={{ whiteSpace: "pre-wrap" }}>{body}</div>
        </div>
      ) : (
        <div className="grid gap-3">
          {/* Title */}
          <input
            type="text"
            placeholder="Post title"
            value={title}
            onChange={(e) => {
              setTitle(e.target.value);
              if (!post) setSlug(autoSlug(e.target.value));
              markDirty();
            }}
            className="w-full rounded-lg border border-slate-200 px-3 py-2.5 text-lg font-semibold focus:border-atlantic focus:outline-none"
          />

          {/* Slug */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slatedark/50 shrink-0">Slug:</span>
            <input
              type="text"
              value={slug}
              onChange={(e) => { setSlug(e.target.value.toLowerCase().replace(/\s/g, "-")); markDirty(); }}
              className={`flex-1 rounded border px-2 py-1 font-mono text-xs focus:outline-none ${slugError ? "border-red-400 focus:border-red-400" : "border-slate-200 focus:border-atlantic"}`}
            />
            {slugError && <span className="text-xs text-red-600">{slugError}</span>}
          </div>

          {/* Cover image */}
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs text-slatedark/50">Cover image</span>
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading}
                className="rounded bg-slate-100 px-2 py-0.5 text-xs hover:bg-slate-200 disabled:opacity-50"
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
                <img src={coverImageUrl} alt="Cover" className="h-24 rounded-lg object-cover" />
                <button
                  onClick={() => { setCoverImageUrl(""); markDirty(); }}
                  className="absolute -right-2 -top-2 rounded-full bg-white border border-slate-200 px-1.5 py-0.5 text-xs text-red-600 hover:bg-red-50"
                >
                  ✕
                </button>
              </div>
            ) : (
              <input
                type="url"
                placeholder="Or paste a URL…"
                value={coverImageUrl}
                onChange={(e) => { setCoverImageUrl(e.target.value); markDirty(); }}
                className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm focus:border-atlantic focus:outline-none"
              />
            )}
          </div>

          {/* Excerpt */}
          <textarea
            placeholder="Short excerpt (shown on listing page)…"
            value={excerpt}
            onChange={(e) => { setExcerpt(e.target.value); markDirty(); }}
            rows={2}
            className="w-full resize-y rounded-lg border border-slate-200 px-3 py-2.5 text-sm focus:border-atlantic focus:outline-none"
          />

          {/* Body */}
          <textarea
            placeholder="Post body (Markdown supported)…"
            value={body}
            onChange={(e) => { setBody(e.target.value); markDirty(); }}
            rows={22}
            className="w-full resize-y rounded-lg border border-slate-200 px-3 py-2.5 font-mono text-sm focus:border-atlantic focus:outline-none"
          />

          {/* Tags */}
          <input
            type="text"
            placeholder="Tags (comma-separated: security, tls, headers)"
            value={tags}
            onChange={(e) => { setTags(e.target.value); markDirty(); }}
            className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm focus:border-atlantic focus:outline-none"
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
        <input
          type="search"
          placeholder="Filter by action…"
          className="flex-1 min-w-36 rounded-lg border border-slate-200 px-3 py-2 text-sm focus:outline-none focus:border-atlantic"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1); }}
        />
        <input
          type="search"
          placeholder="Filter by actor email…"
          className="flex-1 min-w-36 rounded-lg border border-slate-200 px-3 py-2 text-sm focus:outline-none focus:border-atlantic"
          value={actor}
          onChange={(e) => { setActor(e.target.value); setPage(1); }}
        />
        <span className="text-xs text-slatedark/50">{total} events</span>
      </div>

      <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 bg-slate-50 text-left text-xs text-slatedark/60">
              <th className="px-4 py-3">When</th>
              <th className="px-4 py-3">Actor</th>
              <th className="px-4 py-3">Action</th>
              <th className="px-4 py-3">Resource</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 ? (
              <tr><td colSpan={4} className="px-4 py-8 text-center text-slatedark/40">No audit events found</td></tr>
            ) : (
              logs.map((l) => (
                <tr key={l.id} className="border-b border-slate-50 hover:bg-slate-50/50">
                  <td className="px-4 py-2 text-xs text-slatedark/50 whitespace-nowrap">{reltime(l.created_at)}</td>
                  <td className="px-4 py-2 font-mono text-xs text-slatedark/80 max-w-40 truncate">{l.actor_email}</td>
                  <td className="px-4 py-2 font-mono text-xs text-atlantic">{l.action}</td>
                  <td className="px-4 py-2 text-xs text-slatedark/60">
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
          <button disabled={page === 1} onClick={() => setPage((p) => p - 1)} className="rounded border px-3 py-1 text-xs disabled:opacity-40">← Prev</button>
          <span className="px-2 py-1 text-xs text-slatedark/50">Page {page}</span>
          <button disabled={page * PAGE_SIZE >= total} onClick={() => setPage((p) => p + 1)} className="rounded border px-3 py-1 text-xs disabled:opacity-40">Next →</button>
        </div>
      )}
    </div>
  );
}

// ─── Root Page ────────────────────────────────────────────────────────────────

export default function AdminPage() {
  const [authState, setAuthState] = useState<"loading" | "signed-out" | "unauthorized" | "ready">("loading");
  const [session, setSession] = useState<Session | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("overview");

  useEffect(() => {
    (async () => {
      const s = await getSession();
      if (!s) { setAuthState("signed-out"); return; }

      // Verify admin access — 10s timeout so a misconfigured API route
      // (e.g. missing SUPABASE_SERVICE_ROLE_KEY) doesn't spin forever.
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

      if (res.status === 403) { setAuthState("unauthorized"); return; }
      if (!res.ok) {
        // 404 = API route not deployed; 500 = missing env vars.
        // Either way, show a useful error rather than spinning.
        setAuthState("unauthorized");
        return;
      }

      setSession(s);
      setAuthState("ready");
    })().catch(() => setAuthState("unauthorized"));
  }, []);

  if (authState === "loading") {
    return <div className="px-6 py-20 text-center text-sm text-slatedark/40">Loading…</div>;
  }

  if (authState === "signed-out") {
    return (
      <div className="mx-auto max-w-md px-6 py-24 text-center">
        <h1 className="text-2xl font-bold text-atlantic">Sign in required</h1>
        <Link href="/login" className="mt-6 inline-block text-atlantic underline">Sign in</Link>
      </div>
    );
  }

  if (authState === "unauthorized") {
    return (
      <div className="mx-auto max-w-md px-6 py-24 text-center">
        <h1 className="text-2xl font-bold text-atlantic">Admin access required</h1>
        <div className="mt-4 space-y-2 text-left text-sm text-slatedark/70">
          <p>Could not verify admin access. Common causes:</p>
          <ul className="list-disc pl-5 space-y-1">
            <li>You&apos;re not signed in — <Link href="/login" className="underline">sign in first</Link></li>
            <li>Your account doesn&apos;t have <code className="font-mono bg-slate-100 px-1 rounded">is_admin = true</code> in Supabase</li>
            <li><code className="font-mono bg-slate-100 px-1 rounded">SUPABASE_URL</code> or <code className="font-mono bg-slate-100 px-1 rounded">SUPABASE_SERVICE_ROLE_KEY</code> not set in Azure app settings</li>
            <li>API routes not deployed yet — wait for CI to finish</li>
          </ul>
        </div>
        <Link href="/dashboard" className="mt-6 inline-block text-atlantic underline">Back to dashboard</Link>
      </div>
    );
  }

  const tabs: { key: Tab; label: string }[] = [
    { key: "overview", label: "Overview" },
    { key: "customers", label: "Customers" },
    { key: "scans", label: "Scans" },
    { key: "queue", label: "Queue" },
    { key: "blog", label: "Blog / CMS" },
    { key: "audit", label: "Audit log" },
  ];

  return (
    <div className="mx-auto max-w-7xl px-4 py-8">
      {/* Header */}
      <div className="mb-6 flex items-baseline justify-between">
        <div>
          <p className="font-mono text-xs text-atlantic/50">// hebrides-cyber</p>
          <h1 className="text-2xl font-bold text-atlantic">Admin</h1>
        </div>
        <Link href="/dashboard" className="text-sm text-slatedark/60 hover:text-slatedark">← Dashboard</Link>
      </div>

      {/* Tabs */}
      <nav className="mb-6 flex gap-1 border-b border-slate-200">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setActiveTab(t.key)}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === t.key
                ? "border-b-2 border-atlantic text-atlantic"
                : "text-slatedark/60 hover:text-slatedark"
            }`}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {/* Content */}
      <div>
        {session && (
          <>
            {activeTab === "overview" && <OverviewTab token={session.access_token} />}
            {activeTab === "customers" && <CustomersTab token={session.access_token} />}
            {activeTab === "scans" && <ScansTab token={session.access_token} />}
            {activeTab === "queue" && <QueueTab token={session.access_token} />}
            {activeTab === "blog" && <BlogTab token={session.access_token} />}
            {activeTab === "audit" && <AuditTab token={session.access_token} />}
          </>
        )}
      </div>
    </div>
  );
}

import { capStatus } from "@/lib/usageCapStatus";

// Shared by every admin tab (src/app/admin/_tabs/*). Kept out of page.tsx so
// each tab can be code-split.


export type Metrics = {
  totalCustomers: number;
  activeSubscriptions: number;
  totalScans: number;
  scansLast30d: number;
  scansByStatus: Record<string, number>;
  planBreakdown: { plan: string; count: number }[];
  mrrUsd: number;
  revenue: {
    payingMrrGbp: number;
    payingCount: number;
    compedCount: number;
    bespokeCount: number;
    byPlan: { plan: string; count: number; mrrGbp: number }[];
    pastDueCount: number;
    newSubs30d: number;
    cancellations30d: number;
    churnRatePct: number | null;
  };
  recentSignups: { id: string; email: string; company_name: string | null; created_at: string }[];
};

export type Customer = {
  id: string;
  email: string;
  company_name: string | null;
  is_admin: boolean;
  plan: string | null;
  subscription_status: string | null;
  plan_source: string | null;
  grant_reason: string | null;
  scan_count: number;
  created_at: string;
};

export type CustomerDetail = {
  user: { id: string; email: string; company_name: string | null; is_admin: boolean; created_at: string };
  subscription: {
    plan: string | null;
    status: string | null;
    source: string | null;
    grant_reason: string | null;
    stripe_customer_id: string | null;
    updated_at: string | null;
  } | null;
  scans: { id: string; targetUrl: string; status: string; score: number | null; createdAt: string }[];
  scanCount: number;
  usage: {
    monitoredTargets: { count: number; cap: number | null };
    teamMembers: { count: number; cap: number } | null;
    freeScans: { count: number; allowed: number } | null;
  };
};

export type ScanRow = {
  id: string;
  ownerEmail: string;
  ownerCompany: string | null;
  targetUrl: string;
  status: string;
  score: number | null;
  summary: string | null;
  errorDetail: string | null;
  jobId: string | null;
  createdAt: string;
};

export type QueueData = {
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

export type QueueJob = {
  id: string;
  scanId: string | null;
  targetUrl: string;
  addedAt: number;
  startedAt: number | null;
  finishedAt: number | null;
  progress: number;
};

export type BlogPost = {
  id: string;
  slug: string;
  title: string;
  excerpt: string;
  status: "draft" | "published" | "scheduled";
  published_at: string | null;
  updated_at: string;
  tags: string[];
  cover_image_url: string | null;
};

export type BlogPostFull = BlogPost & {
  body: string;
  author_id: string;
  meta_description: string | null;
  og_image: string | null;
};

export type AuditLog = {
  id: string;
  actor_email: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  created_at: string;
};

export type Tab = "overview" | "customers" | "scans" | "queue" | "blog" | "audit" | "tools" | "gdpr" | "email" | "contacts";

export type ContactEnquiry = {
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

export function statusBadge(status: string) {
  const map: Record<string, string> = {
    completed: "bg-neon/20 text-neon",
    running:   "bg-seafoam/20 text-seafoam",
    pending:   "bg-amber-400/20 text-amber-400",
    failed:    "bg-red-400/20 text-red-400",
    published: "bg-neon/20 text-neon",
    scheduled: "bg-seafoam/20 text-seafoam",
    draft:     "bg-cyberborder text-cybertext/60",
    active:    "bg-seafoam/20 text-seafoam",
    waiting:   "bg-amber-400/20 text-amber-400",
  };
  return (
    <span className={`inline-block rounded-sm px-2 py-0.5 text-xs font-medium ${map[status] ?? "bg-cyberborder text-cybertext/60"}`}>
      {status}
    </span>
  );
}

export function reltime(ts: string | number) {
  const ms = typeof ts === "number" ? ts : new Date(ts).getTime();
  const diff = Date.now() - ms;
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)}h ago`;
  return `${Math.round(diff / 86_400_000)}d ago`;
}

export async function apiFetch<T>(path: string, token: string, opts?: RequestInit): Promise<T> {
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

export function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <p className="text-2xl font-bold text-neon">{value}</p>
      <p className="mt-0.5 text-sm font-medium text-cybertext/70">{label}</p>
      {sub && <p className="mt-1 text-xs text-cybermuted">{sub}</p>}
    </div>
  );
}

export const CAP_STATUS_STYLE: Record<string, string> = {
  ok: "text-cybertext/50",
  near: "text-amber-400",
  at: "text-red-400",
  unknown: "text-cybermuted",
};

/** One "N of cap used" line, flagged amber/red once a real plan ceiling is close or reached. */
export function UsageRow({ label, count, cap }: { label: string; count: number; cap: number | null }) {
  const status = capStatus(count, cap);
  return (
    <p className={`text-xs ${CAP_STATUS_STYLE[status]}`}>
      {label}: {count}
      {cap !== null && ` of ${cap}`} used
      {status === "at" && " — at cap"}
      {status === "near" && " — near cap"}
    </p>
  );
}

export function AdminInput({ className = "", ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={`rounded-lg border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-hidden transition-colors ${className}`}
      {...props}
    />
  );
}

export function AdminTextarea({ className = "", ...props }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={`rounded-lg border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-hidden transition-colors ${className}`}
      {...props}
    />
  );
}

export function AdminSelect({ className = "", ...props }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={`rounded-lg border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext focus:border-neon focus:outline-hidden transition-colors ${className}`}
      {...props}
    />
  );
}


"use client";

import { useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";
import { getSession } from "@/lib/auth";
import Link from "next/link";
import ScanList, { Scan } from "@/components/ScanList";

const PAGE_SIZE = 50;

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(false);
  const [offset, setOffset] = useState(0);
  const [userId, setUserId] = useState<string | null>(null);

  async function fetchScans(from: number, append: boolean, currentUserId: string) {
    const { data } = await supabase
      .from("scans")
      .select("id, target_url, status, created_at, owner, scan_results(score)")
      .order("created_at", { ascending: false })
      .range(from, from + PAGE_SIZE - 1);

    const page = (data ?? []) as Array<{
      id: string; target_url: string; status: Scan["status"]; created_at: string;
      owner: string; scan_results: { score?: number | null }[] | null;
    }>;

    // Team membership (Account -> Team) can put someone else's scans in this
    // list — resolve their email so the row says whose it is.
    const otherOwnerIds = [...new Set(page.filter((r) => r.owner !== currentUserId).map((r) => r.owner))];
    const emailByOwner = new Map<string, string>();
    if (otherOwnerIds.length > 0) {
      const { data: profiles } = await supabase.from("users").select("id, email").in("id", otherOwnerIds);
      for (const p of profiles ?? []) emailByOwner.set(p.id, p.email);
    }

    const rows = page.map((s) => ({
      id: s.id,
      target_url: s.target_url,
      status: s.status,
      created_at: s.created_at,
      score: s.scan_results?.[0]?.score ?? null,
      sharedByEmail: s.owner !== currentUserId ? emailByOwner.get(s.owner) ?? null : null,
    })) as Scan[];

    if (append) {
      setScans((prev) => [...prev, ...rows]);
    } else {
      setScans(rows);
    }
    setHasMore(rows.length === PAGE_SIZE);
    return rows.length;
  }

  useEffect(() => {
    (async () => {
      const session = await getSession();
      if (!session) return;
      setUserId(session.user.id);
      await fetchScans(0, false, session.user.id);
    })().finally(() => setLoading(false));
  }, []);

  async function loadMore() {
    if (!userId) return;
    setLoadingMore(true);
    const next = offset + PAGE_SIZE;
    await fetchScans(next, true, userId);
    setOffset(next);
    setLoadingMore(false);
  }

  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      <div className="bg-grid pointer-events-none fixed inset-0 opacity-20" />
      <div className="relative mx-auto max-w-4xl px-4 py-10 sm:px-6 space-y-6">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="font-mono text-xs text-neon/50" aria-hidden="true">$ ./scans --all</p>
            <h1 className="text-2xl font-bold text-cybertext sm:text-3xl">All Scans</h1>
          </div>
          <Link
            href="/dashboard"
            className="rounded-md border border-cyberborder px-4 py-2 text-sm font-medium text-cybertext/70 hover:border-neon hover:text-neon transition-colors"
          >
            ← Dashboard
          </Link>
        </div>

        {loading ? (
          <p className="text-sm text-cybertext/30 font-mono">// loading…</p>
        ) : (
          <>
            <ScanList scans={scans} />
            {hasMore && (
              <div className="text-center">
                <button
                  onClick={loadMore}
                  disabled={loadingMore}
                  className="rounded-md border border-cyberborder px-6 py-2.5 text-sm text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-40 transition-colors"
                >
                  {loadingMore ? "Loading…" : "Load more"}
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

"use client";

import { useCallback, useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";
import ScanList, { Scan } from "@/components/ScanList";
import RunScanForm from "@/components/RunScanForm";
import { useAppSession } from "@/components/app-shell/AppShell";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";

const PAGE_SIZE = 50;

type ScanRow = {
  id: string;
  target_url: string;
  status: Scan["status"];
  created_at: string;
  owner: string;
  scan_results: { score?: number | null }[] | null;
};

export default function ScansPage() {
  const { userId } = useAppSession();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchPage = useCallback(
    async (from: number): Promise<Scan[]> => {
      const { data, error: fetchError } = await supabase
        .from("scans")
        .select("id, target_url, status, created_at, owner, scan_results(score)")
        .order("created_at", { ascending: false })
        .range(from, from + PAGE_SIZE - 1);
      if (fetchError) throw new Error(fetchError.message);

      const page = (data ?? []) as ScanRow[];

      // Team membership (Account → Team) can put someone else's scans in this
      // list — resolve their email so the row says whose it is.
      const otherOwnerIds = [...new Set(page.filter((r) => r.owner !== userId).map((r) => r.owner))];
      const emailByOwner = new Map<string, string>();
      if (otherOwnerIds.length > 0) {
        const { data: profiles } = await supabase.from("users").select("id, email").in("id", otherOwnerIds);
        for (const p of profiles ?? []) emailByOwner.set(p.id, p.email);
      }

      return page.map((s) => ({
        id: s.id,
        target_url: s.target_url,
        status: s.status,
        created_at: s.created_at,
        score: s.scan_results?.[0]?.score ?? null,
        sharedByEmail: s.owner !== userId ? emailByOwner.get(s.owner) ?? null : null,
      }));
    },
    [userId]
  );

  const reload = useCallback(async () => {
    try {
      const rows = await fetchPage(0);
      setScans(rows);
      setHasMore(rows.length === PAGE_SIZE);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  }, [fetchPage]);

  useEffect(() => {
    let cancelled = false;
    fetchPage(0)
      .then((rows) => {
        if (cancelled) return;
        setScans(rows);
        setHasMore(rows.length === PAGE_SIZE);
      })
      .catch((err) => {
        if (!cancelled) setError((err as Error).message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [fetchPage]);

  async function loadMore() {
    setLoadingMore(true);
    try {
      // Offset by what's on screen rather than a page counter, so a delete
      // in between doesn't make the next page skip a row.
      const rows = await fetchPage(scans.length);
      setScans((prev) => [...prev, ...rows]);
      setHasMore(rows.length === PAGE_SIZE);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoadingMore(false);
    }
  }

  async function deleteScan(scanId: string) {
    // scan_results.scan_id is `on delete cascade` (001_init.sql), so deleting
    // the scans row also removes its result.
    const { error: deleteError } = await supabase.from("scans").delete().eq("id", scanId);
    if (deleteError) throw new Error(deleteError.message);
    setScans((prev) => prev.filter((s) => s.id !== scanId));
  }

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="$ ./scans"
        title="Scans"
        description="Run an on-demand scan, and review or clean up every scan on your account."
      />

      <RunScanForm onScanSettled={reload} />

      {error && <Alert variant="danger" title="Couldn't load your scans">{error}</Alert>}

      {loading ? (
        <Skeleton className="h-64 rounded-xl" />
      ) : (
        <div id="scan-history" className="scroll-mt-6 space-y-4">
          <ScanList scans={scans} onDelete={deleteScan} />
          {hasMore && (
            <div className="text-center">
              <Button variant="secondary" onClick={loadMore} disabled={loadingMore}>
                {loadingMore ? "Loading…" : "Load more"}
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

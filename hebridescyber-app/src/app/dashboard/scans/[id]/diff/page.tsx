"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";
import DiffView from "@/components/DiffView";
import { listCompletedScansForTarget, type ScanListEntry } from "@/lib/clientScanHistory";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";

export default function ScanDiffPage() {
  const params = useParams<{ id: string }>();
  const [targetUrl, setTargetUrl] = useState<string | null>(null);
  const [scans, setScans] = useState<ScanListEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!params?.id) return;
    (async () => {
      const { data } = await supabase.from("scan_results").select("results").eq("scan_id", params.id).maybeSingle();
      const url = (data?.results as { target_url?: string } | undefined)?.target_url;
      if (!url) {
        setLoading(false);
        return;
      }
      setTargetUrl(url);
      const list = await listCompletedScansForTarget(url);
      setScans(list);
      setLoading(false);
    })();
  }, [params?.id]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="$ ./diff"
        title={<span className="break-all">{targetUrl ?? "Compare scans"}</span>}
        description="See exactly what changed between two scans of the same site."
        actions={
          <Button asChild variant="secondary">
            <Link href={`/dashboard/scans/${params?.id}`}>← Back to report</Link>
          </Button>
        }
      />

      {loading ? (
        <Skeleton className="h-64 rounded-xl" />
      ) : !targetUrl || !params?.id ? (
        <Alert variant="danger" title="Could not load this scan">
          It may have been deleted, or it hasn&apos;t finished yet.{" "}
          <Link href="/dashboard/scans" className="font-medium text-neon hover:underline">
            View all scans
          </Link>
        </Alert>
      ) : (
        <DiffView scans={scans} initialScanId={params.id} />
      )}
    </div>
  );
}

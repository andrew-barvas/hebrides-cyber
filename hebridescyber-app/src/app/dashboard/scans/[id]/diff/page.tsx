"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { supabase } from "@/lib/supabaseClient";
import DiffView from "@/components/DiffView";
import { listCompletedScansForTarget, type ScanListEntry } from "@/lib/clientScanHistory";

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
    <div className="bg-cyberbg min-h-screen text-cybertext">
      <div className="bg-grid pointer-events-none fixed inset-0 opacity-20" />
      <div className="relative mx-auto max-w-4xl px-4 py-10 sm:px-6 space-y-6">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="font-mono text-xs text-neon/50" aria-hidden="true">$ ./diff</p>
            <h1 className="text-2xl font-bold text-cybertext break-all sm:text-3xl">{targetUrl ?? "Compare scans"}</h1>
          </div>
          <Link
            href={`/dashboard/scans/${params?.id}`}
            className="rounded-md border border-cyberborder px-4 py-2 text-sm font-medium text-cybertext/70 hover:border-neon hover:text-neon transition-colors"
          >
            ← Back to report
          </Link>
        </div>

        {loading ? (
          <p className="font-mono text-sm text-cybertext/30">// loading…</p>
        ) : !targetUrl || !params?.id ? (
          <p className="text-sm text-cybertext/50">Could not load this scan.</p>
        ) : (
          <DiffView scans={scans} initialScanId={params.id} />
        )}
      </div>
    </div>
  );
}

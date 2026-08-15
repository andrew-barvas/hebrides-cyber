"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { supabase } from "@/lib/supabaseClient";

type ScanResult = {
  id: string;
  scan_id: string;
  results: Record<string, unknown>;
  summary: string | null;
  score: number | null;
  created_at: string;
};

// Single scan detail page. Fetches the scan + its results row and renders
// the raw JSON for now. TODO: replace the raw JSON dump with the styled
// Security Score report template (see marketing/04-security-score-template.md)
// once generate-report produces structured output.
export default function ScanDetailPage() {
  const params = useParams<{ id: string }>();
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const { data, error: fetchError } = await supabase
        .from("scan_results")
        .select("id, scan_id, results, summary, score, created_at")
        .eq("scan_id", params.id)
        .maybeSingle();

      if (fetchError) setError(fetchError.message);
      setResult(data as ScanResult | null);
      setLoading(false);
    })();
  }, [params.id]);

  if (loading) return <div className="px-6 py-16 text-center">Loading…</div>;

  if (error) {
    return <div className="px-6 py-16 text-center text-red-600">{error}</div>;
  }

  if (!result) {
    return (
      <div className="px-6 py-16 text-center text-slatedark/60">
        No results yet for this scan — it may still be running.
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="mb-2 text-2xl font-bold text-atlantic">Scan Report</h1>
      <p className="mb-4 text-sm text-slatedark/60">
        Scan ID: {result.scan_id} · Generated{" "}
        {new Date(result.created_at).toLocaleString()}
      </p>
      {result.score !== null && (
        <p className="mb-2 text-lg font-semibold text-atlantic">Score: {result.score} / 100</p>
      )}
      {result.summary && <p className="mb-6 text-sm text-slatedark/80">{result.summary}</p>}

      <div className="mb-8 rounded-lg border border-slate-200 p-4">
        <p className="mb-2 text-sm font-semibold text-atlantic">Embed this score on your site</p>
        <img src={`/api/badge/${result.scan_id}.svg`} alt="Security Score badge" className="mb-2" />
        <code className="block break-all rounded bg-slatedark p-2 text-xs text-slatelight">
          {`<img src="https://hebridescyber.com/api/badge/${result.scan_id}.svg" alt="Security Score" />`}
        </code>
      </div>

      <h2 className="mb-2 text-lg font-semibold text-atlantic">Raw Results</h2>
      <pre className="overflow-x-auto rounded-lg bg-slatedark p-4 text-xs text-slatelight">
        {JSON.stringify(result.results, null, 2)}
      </pre>
    </div>
  );
}

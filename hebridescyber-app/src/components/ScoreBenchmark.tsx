"use client";

// One line under the score on the scan report: how it compares with other
// sites scanned with Hebrides Cyber (scoreBenchmark.ts). Renders nothing while
// the feature is off or the group is too small.
import { useEffect, useState } from "react";
import { benchmarkSentence, type Benchmark } from "@/lib/scoreBenchmark";

export function ScoreBenchmark({ scanId, token }: { scanId: string; token: string }) {
  const [benchmark, setBenchmark] = useState<Benchmark | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/scans/${scanId}/benchmark`, { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => (res.ok ? res.json() : null))
      .then((body: { benchmark?: Benchmark | null } | null) => {
        if (!cancelled) setBenchmark(body?.benchmark ?? null);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [scanId, token]);

  if (!benchmark) return null;
  return (
    <p className="text-sm text-cybertext/80">
      <span className="text-neon">{benchmarkSentence(benchmark)}</span>{" "}
      <span className="text-cybermuted">Each site counts once, by its latest scan; your own sites aren&apos;t included.</span>
    </p>
  );
}

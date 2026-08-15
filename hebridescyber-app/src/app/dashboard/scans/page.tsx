"use client";

import { useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";
import ScanList, { Scan } from "@/components/ScanList";

// Full scans list (same query as the dashboard summary for now — split out
// so pagination/filtering can be added here later without touching the
// dashboard overview).
// TODO: add pagination once scan volume grows past a page or two.
export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const { data } = await supabase
        .from("scans")
        .select("id, target_url, status, created_at")
        .order("created_at", { ascending: false });
      setScans((data ?? []) as Scan[]);
      setLoading(false);
    })();
  }, []);

  return (
    <div className="mx-auto max-w-4xl px-6 py-16">
      <h1 className="mb-8 text-3xl font-bold text-atlantic">All Scans</h1>
      {loading ? <p>Loading…</p> : <ScanList scans={scans} />}
    </div>
  );
}

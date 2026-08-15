"use client";

import { useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";

type Target = { id: string; target_url: string; created_at: string };

// Agency-tier feature: manage the list of sites scheduled-scans.yml scans
// automatically every night (see src/scripts/fetch-scheduled-targets.ts,
// which reads this same monitored_targets table). Plain RLS-protected
// inserts/deletes via the anon client — no Function call needed, this
// table has user-scoped insert/select/delete policies already
// (sql/migrations/001_init.sql).
export default function MonitoredTargets() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [newUrl, setNewUrl] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const { data, error: fetchError } = await supabase
      .from("monitored_targets")
      .select("id, target_url, created_at")
      .order("created_at", { ascending: false });
    if (fetchError) setError(fetchError.message);
    setTargets((data ?? []) as Target[]);
    setLoading(false);
  }

  useEffect(() => {
    load();
  }, []);

  async function addTarget(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const {
      data: { user },
    } = await supabase.auth.getUser();
    if (!user) return;

    const { error: insertError } = await supabase.from("monitored_targets").insert({ owner: user.id, target_url: newUrl });
    if (insertError) {
      setError(insertError.message);
      return;
    }
    setNewUrl("");
    await load();
  }

  async function removeTarget(id: string) {
    await supabase.from("monitored_targets").delete().eq("id", id);
    await load();
  }

  return (
    <div className="mb-10 rounded-lg border border-slate-200 p-6">
      <h2 className="mb-1 text-lg font-semibold text-atlantic">Monitored sites (Agency)</h2>
      <p className="mb-4 text-sm text-slatedark/60">
        Scanned automatically every night — see .github/workflows/scheduled-scans.yml.
      </p>

      <form onSubmit={addTarget} className="mb-4 flex gap-2">
        <input
          type="url"
          required
          placeholder="https://client-site.com"
          value={newUrl}
          onChange={(e) => setNewUrl(e.target.value)}
          className="flex-1 rounded-md border border-slate-300 px-3 py-2 text-sm"
        />
        <button type="submit" className="rounded-md bg-atlantic px-4 py-2 text-sm font-semibold text-white hover:opacity-90">
          Add site
        </button>
      </form>
      {error && <p className="mb-2 text-sm text-red-600">{error}</p>}

      {loading ? (
        <p className="text-sm text-slatedark/60">Loading…</p>
      ) : targets.length === 0 ? (
        <p className="text-sm text-slatedark/60">No monitored sites yet — add one above.</p>
      ) : (
        <ul className="divide-y divide-slate-100 text-sm">
          {targets.map((t) => (
            <li key={t.id} className="flex items-center justify-between py-2">
              <span>{t.target_url}</span>
              <button onClick={() => removeTarget(t.id)} className="text-red-600 hover:underline">
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

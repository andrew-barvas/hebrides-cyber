"use client";

import { useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";

type Target = { id: string; target_url: string; created_at: string };

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
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <h2 className="mb-0.5 font-mono text-xs text-white/40 uppercase tracking-wide">// monitored sites (agency)</h2>
      <p className="mb-4 text-xs text-white/50">
        Scanned automatically every night — see .github/workflows/scheduled-scans.yml.
      </p>

      <form onSubmit={addTarget} className="mb-4 flex flex-col gap-2 sm:flex-row">
        <input
          type="url"
          required
          placeholder="https://client-site.com"
          value={newUrl}
          onChange={(e) => setNewUrl(e.target.value)}
          className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-white placeholder-white/30 focus:border-neon focus:outline-none transition-colors"
        />
        <button
          type="submit"
          className="rounded-md bg-neon px-4 py-2.5 text-sm font-semibold text-cyberbg hover:opacity-90 shadow-glowsm transition-opacity"
        >
          Add site
        </button>
      </form>

      {error && <p className="mb-2 text-sm text-red-400">{error}</p>}

      {loading ? (
        <p className="text-sm text-white/40">Loading…</p>
      ) : targets.length === 0 ? (
        <p className="text-sm text-white/40">No monitored sites yet — add one above.</p>
      ) : (
        <ul className="divide-y divide-cyberborder text-sm">
          {targets.map((t) => (
            <li key={t.id} className="flex items-center justify-between py-2.5">
              <span className="font-mono text-xs text-neon/80">{t.target_url}</span>
              <button
                onClick={() => removeTarget(t.id)}
                className="text-xs text-white/30 hover:text-red-400 transition-colors"
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

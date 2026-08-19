"use client";

import { useCallback, useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";
import { getSession } from "@/lib/auth";

type Connection = { id: string; github_repo: string; connected_at: string };

export default function ConnectRepo() {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(true);
  const [repoInput, setRepoInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Reads go straight through the client's own session — repo_connections'
  // RLS SELECT policy (owner = auth.uid()) already covers this, so there's
  // no API route to call just to list what's connected.
  const load = useCallback(async () => {
    setLoading(true);
    const { data, error: fetchError } = await supabase
      .from("repo_connections")
      .select("id, github_repo, connected_at")
      .order("connected_at", { ascending: false });
    if (!fetchError) setConnections(data ?? []);
    setLoading(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function withToken(): Promise<string | null> {
    const session = await getSession();
    if (!session) {
      setError("Not signed in.");
      return null;
    }
    return session.access_token;
  }

  async function connect(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const token = await withToken();
    if (!token) return;
    setBusy(true);
    try {
      const res = await fetch("/api/account/connect-repo", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ githubRepo: repoInput.trim() }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not connect repository");
      setRepoInput("");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function disconnect(githubRepo: string) {
    setError(null);
    const token = await withToken();
    if (!token) return;
    setBusy(true);
    try {
      const res = await fetch("/api/account/connect-repo", {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ githubRepo }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not disconnect repository");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <details className="rounded-lg border border-cyberborder bg-cyberpanel">
      <summary className="cursor-pointer px-5 py-4 text-sm font-semibold text-cybertext/80 hover:text-cybertext transition-colors">
        Connect a repository <span className="font-normal text-cybertext/40">(for dependency scanning)</span>
      </summary>
      <div className="px-5 pb-5 pt-1 space-y-4">
        <p className="text-sm text-cybertext/60">
          Connect a GitHub repository so scans can check its{" "}
          <code className="text-neon">package.json</code>,{" "}
          <code className="text-neon">requirements.txt</code>, and{" "}
          <code className="text-neon">composer.json</code> dependencies against
          known vulnerabilities. Install the Hebrides Cyber GitHub App on the
          repo first (or add the bot account as a collaborator, if the App
          isn&rsquo;t set up on this deployment yet) — we verify access
          before saving the connection.
        </p>

        <form onSubmit={connect} className="flex flex-col gap-2 sm:flex-row">
          <input
            type="text"
            required
            placeholder="owner/repo"
            value={repoInput}
            onChange={(e) => setRepoInput(e.target.value)}
            className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-white/30 focus:border-neon focus:outline-none transition-colors"
          />
          <button
            disabled={busy || !repoInput.trim()}
            className="rounded-md bg-neon px-4 py-2.5 text-sm font-semibold text-cyberbg hover:opacity-90 disabled:opacity-50 shadow-glowsm transition-opacity"
          >
            {busy ? "Connecting…" : "Connect"}
          </button>
        </form>

        {error && (
          <p className="text-sm text-red-400" role="alert">
            {error}
          </p>
        )}

        {loading ? (
          <p className="font-mono text-xs text-cybertext/30">// loading…</p>
        ) : connections.length === 0 ? (
          <p className="text-xs text-cybertext/40">No repository connected yet.</p>
        ) : (
          <ul className="divide-y divide-cyberborder rounded-lg border border-cyberborder">
            {connections.map((c) => (
              <li key={c.id} className="flex flex-wrap items-center justify-between gap-2 p-3">
                <code className="text-sm text-neon/80 break-all">{c.github_repo}</code>
                <button
                  onClick={() => disconnect(c.github_repo)}
                  disabled={busy}
                  className="text-xs text-cybertext/40 hover:text-red-400 disabled:opacity-40 transition-colors"
                >
                  Disconnect
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </details>
  );
}

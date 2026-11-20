"use client";

import { useCallback, useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";
import { getSession } from "@/lib/auth";
import { repoTargetHost } from "@/lib/repoTargets";

type Connection = { id: string; github_repo: string; connected_at: string; target_host: string | null };

export default function ConnectRepo() {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(true);
  const [repoInput, setRepoInput] = useState("");
  // The monitored site a repository belongs to (migration 077): repo checks
  // run only on scans of that site, never on the owner's other sites.
  const [sites, setSites] = useState<string[]>([]);
  const [siteInput, setSiteInput] = useState("");
  const [linkSite, setLinkSite] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Reads go straight through the client's own session — repo_connections'
  // RLS SELECT policy (owner = auth.uid()) already covers this, so there's
  // no API route to call just to list what's connected.
  const load = useCallback(async () => {
    setLoading(true);
    const { data, error: fetchError } = await supabase
      .from("repo_connections")
      .select("id, github_repo, connected_at, target_host")
      .order("connected_at", { ascending: false });
    if (!fetchError) setConnections(data ?? []);
    const { data: targets } = await supabase.from("monitored_targets").select("target_url");
    const hosts = [...new Set((targets ?? []).map((t) => repoTargetHost((t as { target_url: string }).target_url)).filter((h): h is string => Boolean(h)))].sort();
    setSites(hosts);
    setSiteInput((current) => current || hosts[0] || "");
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

  async function save(githubRepo: string, site: string): Promise<boolean> {
    setError(null);
    const token = await withToken();
    if (!token) return false;
    setBusy(true);
    try {
      const res = await fetch("/api/account/connect-repo", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ githubRepo, targetUrl: site }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not connect repository");
      await load();
      return true;
    } catch (err) {
      setError((err as Error).message);
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function connect(e: React.FormEvent) {
    e.preventDefault();
    if (await save(repoInput.trim(), siteInput)) setRepoInput("");
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
    <details id="connect-repo" open={connections.some((c) => !c.target_host) || undefined} className="scroll-mt-6 rounded-lg border border-cyberborder bg-cyberpanel">
      <summary className="cursor-pointer px-5 py-4 text-sm font-semibold text-cybertext/80 hover:text-cybertext transition-colors">
        Connect a repository <span className="font-normal text-cybermuted">(for dependency scanning)</span>
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

        <p className="text-sm text-cybertext/60">
          Pick the site the repository belongs to. Its checks only run on scans of that site.
        </p>

        {!loading && sites.length === 0 && (
          <p className="text-xs text-cybermuted">Add the site under Assets first, then connect its repository here.</p>
        )}

        <form onSubmit={connect} className="flex flex-col gap-2 sm:flex-row">
          <input
            type="text"
            required
            placeholder="owner/repo"
            value={repoInput}
            onChange={(e) => setRepoInput(e.target.value)}
            className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-hidden transition-colors"
          />
          <select
            aria-label="Site this repository belongs to"
            value={siteInput}
            onChange={(e) => setSiteInput(e.target.value)}
            className="rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext focus:border-neon focus:outline-hidden"
          >
            {sites.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <button
            disabled={busy || !repoInput.trim() || !siteInput}
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
          <p className="font-mono text-xs text-cybermuted">// loading…</p>
        ) : connections.length === 0 ? (
          <p className="text-xs text-cybermuted">No repository connected yet.</p>
        ) : (
          <ul className="divide-y divide-cyberborder rounded-lg border border-cyberborder">
            {connections.map((c) => (
              <li key={c.id} className="flex flex-wrap items-center justify-between gap-2 p-3">
                <div className="min-w-0">
                  <code className="text-sm text-neon/80 break-all">{c.github_repo}</code>
                  {c.target_host ? (
                    <p className="text-xs text-cybermuted">Checked on scans of {c.target_host}</p>
                  ) : (
                    <div className="mt-1 flex flex-wrap items-center gap-2">
                      <p className="text-xs text-warning">Not linked to a site, so it isn&rsquo;t checked.</p>
                      {sites.length > 0 && (
                        <>
                          <select
                            aria-label={`Site for ${c.github_repo}`}
                            value={linkSite[c.id] ?? sites[0]}
                            onChange={(e) => setLinkSite((m) => ({ ...m, [c.id]: e.target.value }))}
                            className="rounded-md border border-cyberborder bg-cyberbg px-2 py-1 text-xs text-cybertext"
                          >
                            {sites.map((s) => (
                              <option key={s} value={s}>
                                {s}
                              </option>
                            ))}
                          </select>
                          <button
                            onClick={() => save(c.github_repo, linkSite[c.id] ?? sites[0])}
                            disabled={busy}
                            className="text-xs font-semibold text-neon hover:opacity-80 disabled:opacity-40"
                          >
                            Link
                          </button>
                        </>
                      )}
                    </div>
                  )}
                </div>
                <button
                  onClick={() => disconnect(c.github_repo)}
                  disabled={busy}
                  className="text-xs text-cybermuted hover:text-red-400 disabled:opacity-40 transition-colors"
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

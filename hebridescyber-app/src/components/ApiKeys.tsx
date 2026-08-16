"use client";

import { useCallback, useEffect, useState } from "react";

type ApiKey = {
  id: string;
  name: string;
  key_prefix: string;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
};

export default function ApiKeys({ token }: { token: string }) {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Held in component state only, never persisted — the server cannot return
  // it again, so it's shown once and lost on navigation. That's the point.
  const [freshKey, setFreshKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/keys", { headers: { Authorization: `Bearer ${token}` } });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not load API keys");
      setKeys(body.keys ?? []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    load();
  }, [load]);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    setError(null);
    try {
      const res = await fetch("/api/keys", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not create key");
      setFreshKey(body.key);
      setName("");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setCreating(false);
    }
  }

  async function revoke(id: string) {
    setError(null);
    try {
      const res = await fetch("/api/keys", {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not revoke key");
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function copyKey() {
    if (!freshKey) return;
    await navigator.clipboard.writeText(freshKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const active = keys.filter((k) => !k.revoked_at);

  return (
    <section className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <h2 className="mb-4 font-mono text-xs text-cybertext/40 uppercase tracking-wide">// api keys</h2>

      <p className="mb-4 text-xs text-cybertext/50 leading-relaxed">
        Use an API key to run scans from CI or scripts:{" "}
        <code className="font-mono text-neon/70">POST /api/v1/scans</code>. Keys only
        work on domains you&apos;ve already verified.
      </p>

      {freshKey && (
        <div className="mb-4 rounded-lg border border-neon/30 bg-neon/10 p-4">
          <p className="mb-2 text-xs font-semibold text-neon">
            Copy this key now — it won&apos;t be shown again.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <code className="flex-1 break-all rounded border border-cyberborder bg-cyberbg px-2 py-1.5 font-mono text-xs text-neon">
              {freshKey}
            </code>
            <button
              onClick={copyKey}
              className="rounded-md border border-neon/40 px-3 py-1.5 text-xs font-medium text-neon hover:bg-neon/10 transition-colors"
            >
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
          <button
            onClick={() => setFreshKey(null)}
            className="mt-3 text-xs text-cybertext/40 hover:text-cybertext/70"
          >
            I&apos;ve saved it — dismiss
          </button>
        </div>
      )}

      {error && <p className="mb-3 text-xs text-red-400" role="alert">{error}</p>}

      <form onSubmit={create} className="mb-4 flex flex-wrap gap-2">
        <input
          type="text"
          required
          maxLength={60}
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Key name (e.g. GitHub Actions)"
          className="min-w-[200px] flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
        />
        <button
          type="submit"
          disabled={creating || !name.trim()}
          className="rounded-md bg-neon px-4 py-2 text-sm font-semibold text-cyberbg shadow-glowsm hover:opacity-90 disabled:opacity-40 transition-opacity"
        >
          {creating ? "Creating…" : "Create key"}
        </button>
      </form>

      {loading ? (
        <p className="font-mono text-xs text-cybertext/30">// loading…</p>
      ) : active.length === 0 ? (
        <p className="text-xs text-cybertext/40">No active keys.</p>
      ) : (
        <ul className="divide-y divide-cyberborder rounded-lg border border-cyberborder">
          {active.map((k) => (
            <li key={k.id} className="flex flex-wrap items-center justify-between gap-2 p-3">
              <div className="min-w-0">
                <p className="text-sm font-medium text-cybertext/80">{k.name}</p>
                <p className="font-mono text-xs text-cybertext/40 break-all">
                  {k.key_prefix}…
                  {k.last_used_at
                    ? ` · last used ${new Date(k.last_used_at).toLocaleDateString("en-GB")}`
                    : " · never used"}
                </p>
              </div>
              <button
                onClick={() => revoke(k.id)}
                className="text-xs text-cybertext/40 hover:text-red-400 transition-colors"
              >
                Revoke
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

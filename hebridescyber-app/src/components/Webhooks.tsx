"use client";

import { useCallback, useEffect, useState } from "react";

type Webhook = {
  id: string;
  name: string | null;
  url: string;
  failure_count: number;
  last_success_at: string | null;
  last_failure_at: string | null;
  disabled_at: string | null;
  created_at: string;
};

export default function Webhooks({ token }: { token: string }) {
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [loading, setLoading] = useState(true);
  const [url, setUrl] = useState("");
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Held in component state only, never persisted — the server won't return
  // it again after creation, so it's shown once and lost on navigation.
  const [freshSecret, setFreshSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/webhooks", { headers: { Authorization: `Bearer ${token}` } });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not load webhooks");
      setWebhooks(body.webhooks ?? []);
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
      const res = await fetch("/api/webhooks", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ url, name }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not create webhook");
      setFreshSecret(body.secret);
      setUrl("");
      setName("");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setCreating(false);
    }
  }

  async function remove(id: string) {
    setError(null);
    try {
      const res = await fetch("/api/webhooks", {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not remove webhook");
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function copySecret() {
    if (!freshSecret) return;
    await navigator.clipboard.writeText(freshSecret);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <section className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <h2 className="mb-4 font-mono text-xs text-cybertext/40 uppercase tracking-wide">// webhooks</h2>

      <p className="mb-4 text-xs text-cybertext/50 leading-relaxed">
        Get a signed POST when a scan completes, instead of polling{" "}
        <code className="font-mono text-neon/70">GET /api/v1/scans/{"{id}"}</code>. Payloads are
        signed with the secret below via an <code className="font-mono text-neon/70">hc-signature</code> header.
      </p>

      {freshSecret && (
        <div className="mb-4 rounded-lg border border-neon/30 bg-neon/10 p-4">
          <p className="mb-2 text-xs font-semibold text-neon">
            Copy this signing secret now — it won&apos;t be shown again.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <code className="flex-1 break-all rounded border border-cyberborder bg-cyberbg px-2 py-1.5 font-mono text-xs text-neon">
              {freshSecret}
            </code>
            <button
              onClick={copySecret}
              className="rounded-md border border-neon/40 px-3 py-1.5 text-xs font-medium text-neon hover:bg-neon/10 transition-colors"
            >
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
          <button
            onClick={() => setFreshSecret(null)}
            className="mt-3 text-xs text-cybertext/40 hover:text-cybertext/70"
          >
            I&apos;ve saved it — dismiss
          </button>
        </div>
      )}

      {error && <p className="mb-3 text-xs text-red-400" role="alert">{error}</p>}

      <form onSubmit={create} className="mb-4 flex flex-wrap gap-2">
        <input
          type="url"
          required
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://your-server.example.com/webhooks/hebrides"
          className="min-w-0 w-full sm:min-w-[240px] flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
        />
        <input
          type="text"
          maxLength={60}
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Label (optional)"
          className="min-w-0 w-full sm:min-w-[140px] sm:w-auto rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
        />
        <button
          type="submit"
          disabled={creating || !url.trim()}
          className="rounded-md bg-neon px-4 py-2 text-sm font-semibold text-cyberbg shadow-glowsm hover:opacity-90 disabled:opacity-40 transition-opacity"
        >
          {creating ? "Creating…" : "Add webhook"}
        </button>
      </form>

      {loading ? (
        <p className="font-mono text-xs text-cybertext/30">// loading…</p>
      ) : webhooks.length === 0 ? (
        <p className="text-xs text-cybertext/40">No webhooks configured.</p>
      ) : (
        <ul className="divide-y divide-cyberborder rounded-lg border border-cyberborder">
          {webhooks.map((w) => (
            <li key={w.id} className="flex flex-wrap items-center justify-between gap-2 p-3">
              <div className="min-w-0">
                <p className="text-sm font-medium text-cybertext/80 break-all">
                  {w.name ? `${w.name} — ` : ""}
                  {w.url}
                </p>
                <p className="font-mono text-xs text-cybertext/40">
                  {w.disabled_at ? (
                    <span className="text-red-400/80">
                      disabled after {w.failure_count} failed deliveries
                    </span>
                  ) : w.last_success_at ? (
                    `last delivered ${new Date(w.last_success_at).toLocaleDateString("en-GB")}`
                  ) : w.last_failure_at ? (
                    <span className="text-amber-400/80">
                      last delivery failed {new Date(w.last_failure_at).toLocaleDateString("en-GB")}
                    </span>
                  ) : (
                    "not yet triggered"
                  )}
                </p>
              </div>
              <button
                onClick={() => remove(w.id)}
                className="text-xs text-cybertext/40 hover:text-red-400 transition-colors"
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

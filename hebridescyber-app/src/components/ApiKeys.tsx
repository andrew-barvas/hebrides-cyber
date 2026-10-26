"use client";

import { useCallback, useEffect, useId, useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/input";

type ApiKey = {
  id: string;
  name: string;
  key_prefix: string;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
  /** Empty = any address. */
  allowed_cidrs: string[];
  scopes?: string[];
  last_blocked_ip: string | null;
  last_blocked_at: string | null;
};

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-GB");
}

function AllowlistEditor({
  apiKey,
  token,
  onSaved,
  onCancel,
}: {
  apiKey: ApiKey;
  token: string;
  onSaved: () => Promise<void>;
  onCancel: () => void;
}) {
  const fieldId = useId();
  const [draft, setDraft] = useState(apiKey.allowed_cidrs.join("\n"));
  const [currentIp, setCurrentIp] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // The address as our API sees it, which is what the allowlist is checked
  // against — not necessarily what a third-party "what's my IP" site shows.
  useEffect(() => {
    let cancelled = false;
    fetch("/api/client-ip")
      .then((res) => (res.ok ? res.json() : null))
      .then((body: { ip?: string } | null) => {
        if (!cancelled && body?.ip) setCurrentIp(body.ip);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const entries = draft.split(/[\s,]+/).filter(Boolean);

  async function save() {
    setSaving(true);
    setError(null);
    try {
      const res = await fetch("/api/keys", {
        method: "PATCH",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ id: apiKey.id, allowed_cidrs: entries }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not save the allowlist");
      await onSaved();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="mt-3 w-full space-y-2 rounded-md border border-cyberborder bg-cyberbg p-3">
      <Label htmlFor={fieldId}>Allowed IP addresses and ranges, one per line</Label>
      <textarea
        id={fieldId}
        rows={3}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        placeholder={"203.0.113.7\n198.51.100.0/24\n2001:db8::/48"}
        spellCheck={false}
        aria-describedby={`${fieldId}-help`}
        className="w-full rounded-md border border-cyberborder bg-cyberpanel px-3 py-2 font-mono text-xs text-cybertext placeholder-cybermuted/60 focus:border-neon transition-colors"
      />
      <p id={`${fieldId}-help`} className="text-xs text-cybermuted leading-relaxed">
        Leave empty to allow any address. From anywhere else this key gets a 401, exactly like an invalid key, so a
        leaked key can&apos;t confirm it&apos;s real. Signing in to the dashboard isn&apos;t affected.
      </p>
      {error && (
        <p className="text-xs text-danger" role="alert">
          {error}
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        <Button size="sm" onClick={save} disabled={saving}>
          {saving ? "Saving…" : "Save allowlist"}
        </Button>
        {currentIp && !entries.includes(currentIp) && (
          <Button size="sm" variant="secondary" onClick={() => setDraft(entries.concat(currentIp).join("\n"))}>
            Add my current IP ({currentIp})
          </Button>
        )}
        <Button size="sm" variant="ghost" onClick={onCancel} disabled={saving}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

export default function ApiKeys({ token }: { token: string }) {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [preset, setPreset] = useState<"full" | "ci" | "read_only">("ci");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Held in component state only, never persisted — the server cannot return
  // it again, so it's shown once and lost on navigation. That's the point.
  const [freshKey, setFreshKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);

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
        body: JSON.stringify({ name, preset }),
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
      <h2 className="mb-4 font-mono text-xs text-cybermuted uppercase tracking-wide">// api keys</h2>

      <p className="mb-4 text-xs text-cybertext/50 leading-relaxed">
        Use an API key to run scans from CI or scripts:{" "}
        <code className="font-mono text-neon/70">POST /api/v1/scans</code>. Keys only
        work on domains you&apos;ve already verified. Ready-made templates for GitHub Actions,
        GitLab, Jenkins, Azure DevOps and Bitbucket are in the{" "}
        <Link href="/docs/ci" className="text-neon hover:underline">
          CI setup guide
        </Link>
        .
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
            className="mt-3 text-xs text-cybermuted hover:text-cybertext/70"
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
          className="min-w-0 flex-1 sm:min-w-[200px] rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
        />
        <label htmlFor="key-preset" className="sr-only">Access level</label>
        <select
          id="key-preset"
          value={preset}
          onChange={(e) => setPreset(e.target.value as typeof preset)}
          className="rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext focus:border-neon focus:outline-none"
        >
          <option value="ci">CI: scan, read results, dependency check</option>
          <option value="read_only">Read-only: results and exports</option>
          <option value="full">Full access</option>
        </select>
        <button
          type="submit"
          disabled={creating || !name.trim()}
          className="rounded-md bg-neon px-4 py-2 text-sm font-semibold text-cyberbg shadow-glowsm hover:opacity-90 disabled:opacity-40 transition-opacity"
        >
          {creating ? "Creating…" : "Create key"}
        </button>
      </form>

      {loading ? (
        <p className="font-mono text-xs text-cybermuted">// loading…</p>
      ) : active.length === 0 ? (
        <p className="text-xs text-cybermuted">No active keys.</p>
      ) : (
        <ul className="divide-y divide-cyberborder rounded-lg border border-cyberborder">
          {active.map((k) => (
            <li key={k.id} className="flex flex-wrap items-center justify-between gap-2 p-3">
              <div className="min-w-0">
                <p className="text-sm font-medium text-cybertext/80">{k.name}</p>
                <p className="font-mono text-xs text-cybermuted break-all">
                  {k.key_prefix}…
                  {k.last_used_at ? ` · last used ${formatDate(k.last_used_at)}` : " · never used"}
                </p>
                <p className="mt-0.5 text-xs text-cybermuted break-all">
                  {(k.scopes ?? []).length > 0 ? `Can: ${(k.scopes ?? []).join(", ")}. ` : ""}
                  {k.allowed_cidrs.length === 0
                    ? "Usable from any IP address"
                    : `Only from ${k.allowed_cidrs.slice(0, 3).join(", ")}${k.allowed_cidrs.length > 3 ? ` +${k.allowed_cidrs.length - 3} more` : ""}`}
                </p>
                {k.last_blocked_at && k.last_blocked_ip && (
                  <p className="mt-0.5 text-xs text-warning break-all">
                    Refused a request from {k.last_blocked_ip} on {formatDate(k.last_blocked_at)} (not on the allowlist)
                  </p>
                )}
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => setEditingId(editingId === k.id ? null : k.id)}
                  aria-expanded={editingId === k.id}
                  className="text-xs text-cybermuted hover:text-neon transition-colors"
                >
                  IP allowlist
                </button>
                <button
                  onClick={() => revoke(k.id)}
                  className="text-xs text-cybermuted hover:text-red-400 transition-colors"
                >
                  Revoke
                </button>
              </div>
              {editingId === k.id && (
                <AllowlistEditor
                  apiKey={k}
                  token={token}
                  onCancel={() => setEditingId(null)}
                  onSaved={async () => {
                    setEditingId(null);
                    await load();
                  }}
                />
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

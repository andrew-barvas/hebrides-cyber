"use client";

// Agency client workspaces: create, rename and delete clients, with per-client
// site counts. Talks to /api/clients (session-only, Agency-gated). Deleting a
// client never deletes its sites; they fall back to "Unassigned".

import { useCallback, useEffect, useState } from "react";
import { getSession } from "@/lib/auth";

type ClientItem = { id: string; name: string; site_count: number };
type Props = { onChanged?: () => void };

async function api(method: string, body?: unknown): Promise<{ ok: boolean; data: Record<string, unknown> }> {
  const session = await getSession();
  if (!session) return { ok: false, data: { error: "Not signed in." } };
  const res = await fetch("/api/clients", {
    method,
    headers: { Authorization: `Bearer ${session.access_token}`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  return { ok: res.ok, data };
}

export default function ClientsManager({ onChanged }: Props) {
  const [clients, setClients] = useState<ClientItem[]>([]);
  const [unassigned, setUnassigned] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [editing, setEditing] = useState<{ id: string; name: string } | null>(null);

  const load = useCallback(async () => {
    const { ok, data } = await api("GET");
    if (!ok) setError((data.error as string) ?? "Could not load clients");
    else {
      setClients((data.clients as ClientItem[]) ?? []);
      setUnassigned((data.unassigned_sites as number) ?? 0);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  async function run(method: string, body: unknown) {
    setError(null);
    const { ok, data } = await api(method, body);
    if (!ok) {
      setError((data.error as string) ?? "Something went wrong");
      return false;
    }
    await load();
    onChanged?.();
    return true;
  }

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (await run("POST", { name })) setName("");
  }

  async function rename(e: React.FormEvent) {
    e.preventDefault();
    if (editing && (await run("PATCH", { id: editing.id, name: editing.name }))) setEditing(null);
  }

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <h2 className="mb-0.5 font-mono text-xs uppercase tracking-wide text-cybermuted">// clients</h2>
      <p className="mb-4 text-xs text-cybermuted">
        Group your monitored sites by client, then switch between them from the header. Deleting a client keeps its sites.
      </p>

      <form onSubmit={create} className="mb-4 flex flex-col gap-2 sm:flex-row">
        <label htmlFor="new-client-name" className="sr-only">
          Client name
        </label>
        <input
          id="new-client-name"
          required
          maxLength={80}
          placeholder="Client name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder:text-cybermuted focus:border-neon focus:outline-none"
        />
        <button type="submit" className="rounded-md bg-neon px-4 py-2.5 text-sm font-semibold text-cyberbg hover:opacity-90">
          Add client
        </button>
      </form>

      {error && (
        <p role="alert" className="mb-2 text-sm text-danger">
          {error}
        </p>
      )}

      {loading ? (
        <p className="text-sm text-cybermuted">Loading…</p>
      ) : clients.length === 0 ? (
        <p className="text-sm text-cybermuted">No clients yet — add one above, then assign sites to it.</p>
      ) : (
        <ul className="divide-y divide-cyberborder text-sm">
          {clients.map((c) => (
            <li key={c.id} className="flex items-center justify-between gap-2 py-2.5">
              {editing?.id === c.id ? (
                <form onSubmit={rename} className="flex flex-1 gap-2">
                  <label htmlFor={`rename-${c.id}`} className="sr-only">
                    Rename {c.name}
                  </label>
                  <input
                    id={`rename-${c.id}`}
                    required
                    maxLength={80}
                    value={editing.name}
                    onChange={(e) => setEditing({ id: c.id, name: e.target.value })}
                    className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-2 py-1 text-sm text-cybertext"
                  />
                  <button type="submit" className="text-xs text-neon hover:underline">
                    Save
                  </button>
                  <button type="button" onClick={() => setEditing(null)} className="text-xs text-cybermuted hover:text-cybertext">
                    Cancel
                  </button>
                </form>
              ) : (
                <>
                  <span className="text-cybertext">
                    {c.name} <span className="text-xs text-cybermuted">· {c.site_count} site{c.site_count === 1 ? "" : "s"}</span>
                  </span>
                  <span className="flex gap-3">
                    <button type="button" onClick={() => setEditing({ id: c.id, name: c.name })} className="text-xs text-cybermuted hover:text-cybertext">
                      Rename
                    </button>
                    <button
                      type="button"
                      aria-label={`Delete ${c.name}`}
                      onClick={() => {
                        if (window.confirm(`Delete ${c.name}? Its ${c.site_count} site(s) will become Unassigned.`)) void run("DELETE", { id: c.id });
                      }}
                      className="text-xs text-cybermuted hover:text-danger"
                    >
                      Delete
                    </button>
                  </span>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
      {!loading && unassigned > 0 && clients.length > 0 && (
        <p className="mt-3 text-xs text-cybermuted">{unassigned} site{unassigned === 1 ? " is" : "s are"} unassigned — pick a client on each site below.</p>
      )}
    </div>
  );
}

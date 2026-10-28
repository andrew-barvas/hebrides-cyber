"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../_shared";

type ToolFlag = { tool: string; disabled: boolean };

export default function ToolsTab({ token }: { token: string }) {
  const [tools, setTools] = useState<ToolFlag[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(() => {
    apiFetch<{ tools: ToolFlag[] }>("/api/admin/tool-flags", token)
      .then((d) => setTools(d.tools))
      .catch((e) => setErr((e as Error).message));
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const toggle = async (tool: string, disabled: boolean) => {
    setBusy(tool);
    setErr(null);
    try {
      await apiFetch("/api/admin/tool-flags", token, {
        method: "PATCH",
        body: JSON.stringify({ tool, disabled }),
      });
      setTools((prev) => prev.map((t) => (t.tool === tool ? { ...t, disabled } : t)));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const disabledCount = tools.filter((t) => t.disabled).length;

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
        <h3 className="font-mono text-xs uppercase tracking-wide text-cybermuted">// scan-tool kill switches</h3>
        <p className="mt-2 text-xs text-cybertext/50">
          Disable an extended-scan tool globally — it stops running on every scan immediately, no deploy needed.
          Use this to stop a tool that&apos;s misbehaving or flooding targets. {disabledCount > 0 && (
            <span className="text-amber-400">{disabledCount} currently disabled.</span>
          )}
        </p>
      </div>
      {err && <p className="text-sm text-red-400">{err}</p>}
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {tools.map((t) => (
          <div key={t.tool} className="flex items-center justify-between rounded-lg border border-cyberborder bg-cyberpanel px-4 py-2.5">
            <span className="font-mono text-sm text-cybertext/80">{t.tool}</span>
            <button
              onClick={() => toggle(t.tool, !t.disabled)}
              disabled={busy === t.tool}
              className={`rounded px-2.5 py-1 text-xs font-medium transition-colors disabled:opacity-40 ${
                t.disabled
                  ? "bg-red-400/10 text-red-400 hover:bg-red-400/20"
                  : "bg-neon/10 text-neon hover:bg-neon/20"
              }`}
            >
              {busy === t.tool ? "…" : t.disabled ? "Disabled — enable" : "Enabled — disable"}
            </button>
          </div>
        ))}
        {tools.length === 0 && !err && <p className="font-mono text-sm text-cybermuted">// loading…</p>}
      </div>
    </div>
  );
}

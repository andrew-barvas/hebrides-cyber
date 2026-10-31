"use client";

import { useCallback, useEffect, useState } from "react";
import { supabase } from "@/lib/supabaseClient";

type Role = { id: string; label: string; externalId: string; roleArn: string | null };

// Cross-account role setup for the Prowler IAM check: we hand out an external
// id, the customer creates a SecurityAudit + ViewOnlyAccess role that trusts
// our scan identity only with that id, then pastes the role ARN back.
export default function AwsRoleConnect() {
  const [roles, setRoles] = useState<Role[]>([]);
  const [platformAccountId, setPlatformAccountId] = useState<string | null>(null);
  const [label, setLabel] = useState("");
  const [roleArns, setRoleArns] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const call = useCallback(async (init?: { label: string; roleArn?: string }) => {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return null;
    return fetch("/api/account/aws-role-credential", {
      method: init ? "POST" : "GET",
      headers: { Authorization: `Bearer ${session.access_token}`, "Content-Type": "application/json" },
      body: init ? JSON.stringify(init) : undefined,
    });
  }, []);

  const load = useCallback(async () => {
    const res = await call();
    if (res?.ok) {
      const json = await res.json();
      setRoles(json.roles ?? []);
      setPlatformAccountId(json.platformAccountId ?? null);
    }
  }, [call]);

  useEffect(() => { load(); }, [load]);

  async function save(init: { label: string; roleArn?: string }) {
    setBusy(true);
    setMessage(null);
    const res = await call(init);
    if (res?.ok) {
      setLabel("");
      await load();
    } else {
      const json = await res?.json().catch(() => null);
      setMessage(json?.error ?? "Failed to save");
    }
    setBusy(false);
  }

  return (
    <div className="mt-6 border-t border-cyberborder pt-4">
      <h4 className="font-mono text-xs font-semibold text-neon mb-2">AWS IAM &amp; privilege-escalation check (cross-account role)</h4>
      <p className="text-xs text-cybertext/50 mb-3">
        Read-only, no access keys. Create a role in your account with the SecurityAudit and ViewOnlyAccess managed
        policies that trusts our scan identity only when it presents the external id below, then paste its ARN.
      </p>
      {message && <div className="mb-3 rounded-sm border border-neon/30 bg-neon/5 px-3 py-2 text-xs text-neon">{message}</div>}

      <ul className="space-y-3 mb-3">
        {roles.map((r) => (
          <li key={r.id} className="rounded-sm border border-cyberborder bg-cyberbg p-3 text-xs text-cybertext space-y-2">
            <div className="font-semibold">{r.label}</div>
            <div>External ID: <code className="font-mono text-neon">{r.externalId}</code></div>
            {r.roleArn ? (
              <div>Role: <code className="font-mono">{r.roleArn}</code></div>
            ) : (
              <>
                <p className="text-cybermuted">
                  Trust policy principal: {platformAccountId ? <code className="font-mono">arn:aws:iam::{platformAccountId}:root</code> : "not available yet — contact support"},
                  with condition <code className="font-mono">sts:ExternalId = {r.externalId}</code>.
                </p>
                <label className="block text-cybertext/60" htmlFor={`arn-${r.id}`}>Role ARN</label>
                <input
                  id={`arn-${r.id}`}
                  value={roleArns[r.id] ?? ""}
                  onChange={(e) => setRoleArns({ ...roleArns, [r.id]: e.target.value })}
                  placeholder="arn:aws:iam::123456789012:role/HebridesCyberAudit"
                  className="w-full rounded-sm border border-cyberborder bg-cyberpanel px-3 py-1.5 text-sm text-cybertext font-mono"
                />
                <button
                  type="button"
                  disabled={busy || !roleArns[r.id]}
                  onClick={() => save({ label: r.label, roleArn: roleArns[r.id] })}
                  className="rounded-sm bg-neon px-3 py-1 text-xs font-semibold text-cyberbg disabled:opacity-50"
                >
                  Save role ARN
                </button>
              </>
            )}
          </li>
        ))}
      </ul>

      <form onSubmit={(e) => { e.preventDefault(); save({ label }); }} className="flex flex-wrap gap-2">
        <label className="sr-only" htmlFor="aws-role-label">Account label</label>
        <input
          id="aws-role-label"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="e.g. Production account"
          required
          className="rounded-sm border border-cyberborder bg-cyberpanel px-3 py-1.5 text-sm text-cybertext"
        />
        <button type="submit" disabled={busy} className="rounded-sm border border-neon/30 px-3 py-1 text-xs text-neon hover:bg-neon/10 disabled:opacity-50">
          Generate external ID
        </button>
      </form>
    </div>
  );
}

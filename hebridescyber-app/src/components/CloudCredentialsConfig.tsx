"use client";

import { useEffect, useState, useCallback } from "react";
import { supabase } from "@/lib/supabaseClient";

type CloudCredential = {
  id: string;
  provider: "aws" | "azure" | "gcp";
  label: string;
  validated_at: string | null;
  created_at: string;
};

type Provider = "aws" | "azure" | "gcp";

export default function CloudCredentialsConfig() {
  const [credentials, setCredentials] = useState<CloudCredential[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const [provider, setProvider] = useState<Provider>("aws");
  const [label, setLabel] = useState("");
  // AWS fields
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretAccessKey, setSecretAccessKey] = useState("");
  const [region, setRegion] = useState("us-east-1");
  // Azure fields
  const [tenantId, setTenantId] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [subscriptionId, setSubscriptionId] = useState("");

  const loadCredentials = useCallback(async () => {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return;

    const res = await fetch("/api/account/cloud-credentials", {
      headers: { Authorization: `Bearer ${session.access_token}` },
    });
    if (res.ok) {
      const json = await res.json();
      setCredentials(json.credentials ?? []);
    }
    setLoading(false);
  }, []);

  useEffect(() => { loadCredentials(); }, [loadCredentials]);

  function resetForm() {
    setLabel("");
    setAccessKeyId("");
    setSecretAccessKey("");
    setRegion("us-east-1");
    setTenantId("");
    setClientId("");
    setClientSecret("");
    setSubscriptionId("");
  }

  async function addCredential(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setMessage(null);

    const { data: { session } } = await supabase.auth.getSession();
    if (!session) { setSaving(false); return; }

    let credentialsPayload: Record<string, string>;
    if (provider === "aws") {
      credentialsPayload = { accessKeyId, secretAccessKey, region };
    } else if (provider === "azure") {
      credentialsPayload = { tenantId, clientId, clientSecret, subscriptionId };
    } else {
      credentialsPayload = {};
    }

    const res = await fetch("/api/account/cloud-credentials", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ provider, label, credentials: credentialsPayload }),
    });

    if (res.ok) {
      setMessage("Credential saved.");
      setShowForm(false);
      resetForm();
      loadCredentials();
    } else {
      const json = await res.json().catch(() => ({ error: "Failed to save" }));
      setMessage(json.error ?? "Failed to save");
    }
    setSaving(false);
  }

  async function deleteCredential(id: string) {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return;

    const res = await fetch("/api/account/cloud-credentials", {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ id }),
    });

    if (res.ok) {
      setMessage("Credential removed.");
      loadCredentials();
    } else {
      const json = await res.json().catch(() => ({ error: "Failed to delete" }));
      setMessage(json.error ?? "Failed to delete");
    }
  }

  const providerLabel: Record<Provider, string> = {
    aws: "AWS",
    azure: "Azure",
    gcp: "GCP",
  };

  return (
    <div className="rounded-lg border border-cyberborder bg-cyberpanel p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-mono text-sm font-semibold text-neon">Cloud Posture Scanning</h3>
        <button
          onClick={() => { setShowForm(!showForm); resetForm(); setMessage(null); }}
          className="rounded border border-neon/30 px-3 py-1 text-xs text-neon hover:bg-neon/10"
        >
          {showForm ? "Cancel" : "+ Add credentials"}
        </button>
      </div>

      <p className="text-xs text-cybertext/50 mb-4">
        Connect your cloud accounts for automated posture checks — public S3 buckets, Azure storage
        misconfigurations, and more. Requires read-only access.
      </p>

      {message && (
        <div className="mb-3 rounded border border-neon/30 bg-neon/5 px-3 py-2 text-xs text-neon">
          {message}
        </div>
      )}

      {showForm && (
        <form onSubmit={addCredential} className="mb-4 space-y-3 rounded border border-cyberborder bg-cyberbg p-4">
          <div>
            <label className="block text-xs text-cybertext/60 mb-1">Provider</label>
            <select
              value={provider}
              onChange={(e) => setProvider(e.target.value as Provider)}
              className="w-full rounded border border-cyberborder bg-cyberpanel px-3 py-1.5 text-sm text-cybertext"
            >
              <option value="aws">AWS</option>
              <option value="azure">Azure</option>
              <option value="gcp" disabled>GCP (coming soon)</option>
            </select>
          </div>

          <div>
            <label className="block text-xs text-cybertext/60 mb-1">Label</label>
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="e.g. Production account"
              required
              className="w-full rounded border border-cyberborder bg-cyberpanel px-3 py-1.5 text-sm text-cybertext"
            />
          </div>

          {provider === "aws" && (
            <>
              <div>
                <label className="block text-xs text-cybertext/60 mb-1">Access Key ID</label>
                <input
                  type="text"
                  value={accessKeyId}
                  onChange={(e) => setAccessKeyId(e.target.value)}
                  placeholder="AKIA..."
                  required
                  className="w-full rounded border border-cyberborder bg-cyberpanel px-3 py-1.5 text-sm text-cybertext font-mono"
                />
              </div>
              <div>
                <label className="block text-xs text-cybertext/60 mb-1">Secret Access Key</label>
                <input
                  type="password"
                  value={secretAccessKey}
                  onChange={(e) => setSecretAccessKey(e.target.value)}
                  required
                  className="w-full rounded border border-cyberborder bg-cyberpanel px-3 py-1.5 text-sm text-cybertext font-mono"
                />
              </div>
              <div>
                <label className="block text-xs text-cybertext/60 mb-1">Region (default: us-east-1)</label>
                <input
                  type="text"
                  value={region}
                  onChange={(e) => setRegion(e.target.value)}
                  className="w-full rounded border border-cyberborder bg-cyberpanel px-3 py-1.5 text-sm text-cybertext font-mono"
                />
              </div>
              <p className="text-xs text-cybermuted">
                Requires: s3:ListBuckets, s3:GetBucketPolicyStatus, s3:GetPublicAccessBlock (read-only).
              </p>
            </>
          )}

          {provider === "azure" && (
            <>
              <div>
                <label className="block text-xs text-cybertext/60 mb-1">Tenant ID</label>
                <input
                  type="text"
                  value={tenantId}
                  onChange={(e) => setTenantId(e.target.value)}
                  required
                  className="w-full rounded border border-cyberborder bg-cyberpanel px-3 py-1.5 text-sm text-cybertext font-mono"
                />
              </div>
              <div>
                <label className="block text-xs text-cybertext/60 mb-1">Client ID</label>
                <input
                  type="text"
                  value={clientId}
                  onChange={(e) => setClientId(e.target.value)}
                  required
                  className="w-full rounded border border-cyberborder bg-cyberpanel px-3 py-1.5 text-sm text-cybertext font-mono"
                />
              </div>
              <div>
                <label className="block text-xs text-cybertext/60 mb-1">Client Secret</label>
                <input
                  type="password"
                  value={clientSecret}
                  onChange={(e) => setClientSecret(e.target.value)}
                  required
                  className="w-full rounded border border-cyberborder bg-cyberpanel px-3 py-1.5 text-sm text-cybertext font-mono"
                />
              </div>
              <div>
                <label className="block text-xs text-cybertext/60 mb-1">Subscription ID</label>
                <input
                  type="text"
                  value={subscriptionId}
                  onChange={(e) => setSubscriptionId(e.target.value)}
                  required
                  className="w-full rounded border border-cyberborder bg-cyberpanel px-3 py-1.5 text-sm text-cybertext font-mono"
                />
              </div>
              <p className="text-xs text-cybermuted">
                Requires: Reader role on the subscription (Storage Account list + properties).
              </p>
            </>
          )}

          <button
            type="submit"
            disabled={saving}
            className="rounded bg-neon px-4 py-1.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90 disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save credentials"}
          </button>
        </form>
      )}

      {loading ? (
        <p className="text-xs text-cybermuted">Loading...</p>
      ) : credentials.length === 0 ? (
        <p className="text-xs text-cybermuted">
          No cloud credentials configured. Add credentials to enable cloud posture scanning.
        </p>
      ) : (
        <ul className="space-y-2">
          {credentials.map((cred) => (
            <li
              key={cred.id}
              className="flex flex-wrap items-center justify-between gap-2 rounded border border-cyberborder bg-cyberbg px-3 py-2"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="inline-block rounded bg-neon/10 px-2 py-0.5 text-xs font-mono text-neon">
                  {providerLabel[cred.provider]}
                </span>
                <span className="text-sm text-cybertext">{cred.label}</span>
                <span className="text-xs text-cybermuted">
                  Added {new Date(cred.created_at).toLocaleDateString()}
                </span>
              </div>
              <button
                onClick={() => deleteCredential(cred.id)}
                className="text-xs text-red-400 hover:text-red-300"
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

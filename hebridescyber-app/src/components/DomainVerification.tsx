"use client";

import { useState } from "react";
import { getSession } from "@/lib/auth";

type StartResponse = {
  domain: string;
  token: string;
  verified: boolean;
  dnsRecord: { type: string; name: string; value: string };
  file: { url: string; contents: string };
};

// Drives the real DNS TXT / file ownership check (src/lib/ownership.ts via
// src/functions/verify-ownership). This is the stronger alternative to the
// dev-only X-Scan-Token echo the quick "Run scan" form on the dashboard
// still falls back to — see docs/security.md.
export default function DomainVerification() {
  const [targetUrl, setTargetUrl] = useState("");
  const [instructions, setInstructions] = useState<StartResponse | null>(null);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function callVerifyOwnership(action: "start" | "check") {
    const functionsUrl = process.env.NEXT_PUBLIC_AZURE_FUNCTIONS_URL;
    const session = await getSession();
    if (!functionsUrl || !session) {
      setError("Not configured or not signed in.");
      return null;
    }
    const res = await fetch(`${functionsUrl}/api/verify-ownership`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.access_token}` },
      body: JSON.stringify({ action, targetUrl }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error ?? `verify-ownership failed (${res.status})`);
    return body;
  }

  async function start(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setVerified(null);
    try {
      const body = (await callVerifyOwnership("start")) as StartResponse;
      setInstructions(body);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function check() {
    setBusy(true);
    setError(null);
    try {
      const body = (await callVerifyOwnership("check")) as { verified: boolean };
      setVerified(body.verified);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <details className="mb-10 rounded-lg border border-slate-200 p-4">
      <summary className="cursor-pointer text-sm font-semibold text-atlantic">
        Verify domain ownership (recommended)
      </summary>
      <p className="mt-3 text-sm text-slatedark/70">
        Prove you control a domain via DNS or a file upload, so scans against
        it don't rely on the quick token-echo shortcut. Propagation can take
        a few minutes after adding the record.
      </p>

      <form onSubmit={start} className="mt-4 flex gap-2">
        <input
          type="url"
          required
          placeholder="https://your-site.com"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          className="flex-1 rounded-md border border-slate-300 px-3 py-2 text-sm"
        />
        <button disabled={busy} className="rounded-md bg-atlantic px-4 py-2 text-sm font-semibold text-white hover:opacity-90 disabled:opacity-50">
          Get instructions
        </button>
      </form>

      {error && <p className="mt-3 text-sm text-red-600">{error}</p>}

      {instructions && (
        <div className="mt-4 space-y-3 rounded-md bg-slate-50 p-4 text-sm">
          <p className="font-medium">Option A — DNS TXT record</p>
          <code className="block break-all rounded bg-slatedark p-2 text-xs text-slatelight">
            {instructions.dnsRecord.name} TXT "{instructions.dnsRecord.value}"
          </code>
          <p className="font-medium">Option B — upload a file</p>
          <p>
            Put this at <code>{instructions.file.url}</code>:
          </p>
          <code className="block break-all rounded bg-slatedark p-2 text-xs text-slatelight">{instructions.file.contents}</code>

          <button
            onClick={check}
            disabled={busy}
            className="mt-2 rounded-md bg-seafoam px-4 py-2 text-sm font-semibold text-slatedark hover:opacity-90 disabled:opacity-50"
          >
            {busy ? "Checking…" : "Check now"}
          </button>

          {verified === true && <p className="text-green-700">Verified ✓ — this domain no longer needs the dev token fallback.</p>}
          {verified === false && <p className="text-amber-700">Not verified yet — DNS changes can take a while to propagate.</p>}
        </div>
      )}
    </details>
  );
}

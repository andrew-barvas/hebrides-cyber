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

export default function DomainVerification() {
  const [targetUrl, setTargetUrl] = useState("");
  const [instructions, setInstructions] = useState<StartResponse | null>(null);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function callVerifyOwnership(action: "start" | "check") {
    const session = await getSession();
    if (!session) {
      setError("Not signed in.");
      return null;
    }
    const res = await fetch("/api/verify-ownership", {
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
    <details open className="rounded-lg border border-cyberborder bg-cyberpanel">
      <summary className="cursor-pointer px-5 py-4 text-sm font-semibold text-cybertext/80 hover:text-cybertext transition-colors">
        Verify domain ownership <span className="font-normal text-cybertext/40">(required before scanning)</span>
      </summary>
      <div className="px-5 pb-5 pt-1 space-y-4">
        <p className="text-sm text-cybertext/60">
          Prove you control a domain via DNS or a file upload before scanning
          it — this confirms you&apos;re authorised to test it, not just that
          you&apos;re logged in. Propagation can take a few minutes after
          adding the record.
        </p>

        <form onSubmit={start} className="flex flex-col gap-2 sm:flex-row">
          <input
            type="url"
            required
            placeholder="https://your-site.com"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2.5 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
          />
          <button
            disabled={busy}
            className="rounded-md bg-neon px-4 py-2.5 text-sm font-semibold text-cyberbg hover:opacity-90 disabled:opacity-50 shadow-glowsm transition-opacity"
          >
            Get instructions
          </button>
        </form>

        {error && <p className="text-sm text-red-400">{error}</p>}

        {instructions && (
          <div className="space-y-3 rounded-md border border-cyberborder bg-cyberbg p-4 text-sm">
            <p className="font-medium text-cybertext/80">Option A — DNS TXT record</p>
            <code className="block break-all rounded border border-cyberborder bg-cyberpanel p-2 text-xs text-neon">
              {instructions.dnsRecord.name} TXT &quot;{instructions.dnsRecord.value}&quot;
            </code>
            <p className="font-medium text-cybertext/80">Option B — upload a file</p>
            <p className="text-cybertext/60">
              Put this at <code className="text-neon">{instructions.file.url}</code>:
            </p>
            <code className="block break-all rounded border border-cyberborder bg-cyberpanel p-2 text-xs text-neon">
              {instructions.file.contents}
            </code>

            <button
              onClick={check}
              disabled={busy}
              className="rounded-md border border-cyberborder px-4 py-2 text-sm font-semibold text-cybertext/70 hover:border-neon hover:text-neon disabled:opacity-50 transition-colors"
            >
              {busy ? "Checking…" : "Check now"}
            </button>

            {verified === true && <p className="text-neon">Verified ✓ — this domain no longer needs the dev token fallback.</p>}
            {verified === false && <p className="text-amber-400">Not verified yet — DNS changes can take a while to propagate.</p>}
          </div>
        )}
      </div>
    </details>
  );
}

"use client";

// Proving control of a domain before scanning it. Two steps against
// /api/verify-ownership: "start" returns the DNS record and file to add,
// "check" looks them up. A failed check comes back with `hints` saying what
// each method found (no TXT record yet, a redirect, the wrong file contents),
// so the customer knows what to fix rather than just "not verified yet".
// Domains already started are listed from `verifications` (owner-readable
// under RLS), so instructions survive a page reload.

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { getSession } from "@/lib/auth";
import { supabase } from "@/lib/supabaseClient";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";

type StartResponse = {
  domain: string;
  token: string;
  verified: boolean;
  dnsRecord: { type: string; name: string; value: string };
  file: { url: string; contents: string };
};

type CheckResponse = { verified: boolean; hints?: string[] };

type KnownDomain = { domain: string; verified: boolean };

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="ghost"
      size="sm"
      aria-label={`Copy ${label}`}
      onClick={async () => {
        await navigator.clipboard?.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }}
    >
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-14 shrink-0 text-xs text-cybermuted">{label}</span>
      <code className="min-w-0 flex-1 break-all rounded border border-cyberborder bg-cyberpanel px-2 py-1 text-xs text-neon">{value}</code>
      <CopyButton text={value} label={label.toLowerCase()} />
    </div>
  );
}

export default function DomainVerification() {
  const [targetUrl, setTargetUrl] = useState("");
  const [known, setKnown] = useState<KnownDomain[]>([]);
  const [instructions, setInstructions] = useState<StartResponse | null>(null);
  const [check, setCheck] = useState<CheckResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadKnown = useCallback(async () => {
    const { data } = await supabase.from("verifications").select("domain, verified_at").order("created_at", { ascending: false });
    setKnown(((data ?? []) as { domain: string; verified_at: string | null }[]).map((v) => ({ domain: v.domain, verified: Boolean(v.verified_at) })));
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- loading the list once on mount
    void loadKnown();
  }, [loadKnown]);

  async function callVerifyOwnership(action: "start" | "check", url: string) {
    const session = await getSession();
    if (!session) throw new Error("Your session has expired. Sign in again.");
    const res = await fetch("/api/verify-ownership", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.access_token}` },
      body: JSON.stringify({ action, targetUrl: url }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error ?? `Verification failed (${res.status})`);
    return body;
  }

  async function start(url: string) {
    setBusy(true);
    setError(null);
    setCheck(null);
    try {
      const body = (await callVerifyOwnership("start", url)) as StartResponse;
      setInstructions(body);
      await loadKnown();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function runCheck() {
    if (!instructions) return;
    setBusy(true);
    setError(null);
    try {
      const body = (await callVerifyOwnership("check", `https://${instructions.domain}`)) as CheckResponse;
      setCheck(body);
      if (body.verified) await loadKnown();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const verifiedHere = check?.verified || instructions?.verified;

  return (
    <details open className="rounded-lg border border-cyberborder bg-cyberpanel">
      <summary className="cursor-pointer px-5 py-4 text-sm font-semibold text-cybertext/80 transition-colors hover:text-cybertext">
        Verify domain ownership <span className="font-normal text-cybermuted">(required before scanning)</span>
      </summary>
      <div className="space-y-4 px-5 pb-5 pt-1">
        <p className="text-sm text-cybermuted">
          We only scan sites you control. Scanning a site tests it the way an attacker would, so we ask for proof first:
          add a DNS record, or upload a small file. You only do this once per domain.
        </p>

        {known.length > 0 && (
          <ul aria-label="Your domains" className="divide-y divide-cyberborder rounded-md border border-cyberborder text-sm">
            {known.map((d) => (
              <li key={d.domain} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
                <span className="font-mono text-cybertext/80">{d.domain}</span>
                {d.verified ? (
                  <span className="text-xs font-semibold text-neon">Verified</span>
                ) : (
                  <Button variant="secondary" size="sm" disabled={busy} onClick={() => start(`https://${d.domain}`)}>
                    Show instructions
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void start(targetUrl);
          }}
          className="flex flex-col gap-2 sm:flex-row sm:items-end"
        >
          <div className="flex-1 space-y-1.5">
            <Label htmlFor="verify-target-url">Website to verify</Label>
            <Input id="verify-target-url" type="url" required placeholder="https://your-site.com" value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} />
          </div>
          <Button type="submit" disabled={busy}>
            Get instructions
          </Button>
        </form>

        {error && <Alert variant="danger">{error}</Alert>}

        {instructions && (
          <div className="space-y-4 rounded-md border border-cyberborder bg-cyberbg p-4 text-sm">
            <p className="font-medium text-cybertext">
              Verifying <span className="font-mono text-neon">{instructions.domain}</span>. Do <strong>one</strong> of these:
            </p>

            <div className="space-y-2">
              <p className="font-medium text-cybertext/80">Option A: add a DNS record</p>
              <p className="text-xs text-cybermuted">
                In your domain&apos;s DNS settings (your registrar or host), add a TXT record. If the name field doesn&apos;t accept
                the full domain, use <code className="text-neon">@</code>.
              </p>
              <Field label="Type" value="TXT" />
              <Field label="Name" value={instructions.dnsRecord.name} />
              <Field label="Value" value={instructions.dnsRecord.value} />
            </div>

            <div className="space-y-2">
              <p className="font-medium text-cybertext/80">Option B: upload a file</p>
              <p className="text-xs text-cybermuted">Create a plain text file containing only the token, at exactly this address:</p>
              <Field label="URL" value={instructions.file.url} />
              <Field label="Content" value={instructions.file.contents} />
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <Button variant="secondary" onClick={runCheck} disabled={busy}>
                {busy ? "Checking…" : "Check now"}
              </Button>
              <span className="text-xs text-cybermuted">New DNS records can take a few minutes to appear. You can check again any time.</span>
            </div>

            <div aria-live="polite">
              {verifiedHere ? (
                <Alert variant="success" title={`${instructions.domain} is verified`}>
                  <p>
                    You can now scan it.{" "}
                    <Link href="/dashboard/scans#run-a-scan" className="font-medium text-neon hover:underline">
                      Run a scan →
                    </Link>
                  </p>
                </Alert>
              ) : check ? (
                <Alert variant="warning" title="Not verified yet">
                  {check.hints?.length ? (
                    <ul className="list-disc space-y-1 pl-4">
                      {check.hints.map((h) => (
                        <li key={h}>{h}</li>
                      ))}
                    </ul>
                  ) : (
                    <p>We couldn&apos;t find the record or the file yet. DNS changes can take a while to appear.</p>
                  )}
                </Alert>
              ) : null}
            </div>
          </div>
        )}
      </div>
    </details>
  );
}

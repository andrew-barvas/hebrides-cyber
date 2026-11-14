"use client";

import Link from "next/link";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { InstantCheckResult } from "@/lib/instantCheck";

const SEVERITY_STYLE: Record<string, string> = {
  critical: "bg-red-100 text-red-800",
  high: "bg-orange-100 text-orange-800",
  medium: "bg-yellow-100 text-yellow-800",
  low: "bg-blue-100 text-blue-800",
};

export default function InstantCheck() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<InstantCheckResult | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/instant-check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }) });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) setError(body.error ?? "The check failed. Please try again.");
      else setResult(body as InstantCheckResult);
    } catch {
      setError("Could not reach the service. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <form onSubmit={submit} className="flex flex-col gap-3 sm:flex-row">
        <label htmlFor="instant-url" className="sr-only">Website address</label>
        <Input
          id="instant-url"
          type="text"
          inputMode="url"
          autoComplete="off"
          placeholder="example.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="h-auto flex-1 px-4 py-3 text-base"
        />
        <Button type="submit" size="lg" disabled={busy || url.trim() === ""}>
          {busy ? "Checking…" : "Check now"}
        </Button>
      </form>

      <div role="status" aria-live="polite" className="mt-6">
        {error && <Alert variant="danger">{error}</Alert>}
        {result && (
          <section aria-label="Check result" className="rounded-lg border border-cyberborder bg-cyberpanel p-6">
            <p className="text-sm text-cybermuted">{result.target}</p>
            <p className="mt-1 text-4xl font-bold">{result.score}<span className="text-lg font-normal text-cybermuted"> / 100</span></p>
            <p className="mt-1 text-cybertext/80">
              {result.total === 0 ? "No problems found in the TLS, headers and email checks." : `${result.total} thing${result.total === 1 ? "" : "s"} to fix in the TLS, headers and email checks.`}
            </p>
            {result.findings.length > 0 && (
              <ul className="mt-4 space-y-3">
                {result.findings.map((f) => (
                  <li key={f.title} className="rounded-md border border-cyberborder p-3">
                    <span className={`mr-2 rounded px-2 py-0.5 text-xs font-semibold uppercase ${SEVERITY_STYLE[f.severity] ?? "bg-slate-100 text-slate-800"}`}>{f.severity}</span>
                    <span className="font-medium">{f.title}</span>
                    <p className="mt-1 text-sm text-cybermuted">{f.detail}</p>
                  </li>
                ))}
              </ul>
            )}
            {result.hidden > 0 && <p className="mt-3 text-sm text-cybermuted">and {result.hidden} more.</p>}
            <div className="mt-5 rounded-md border border-cyberborder bg-cyberbg p-4 text-sm text-cybertext/80">
              This is a light check of what any visitor can see. A full scan, after you verify you own the site, adds exposed files, vulnerable software, open ports and step-by-step fixes.{" "}
              <Link href="/signup" className="font-semibold text-neon underline">Create a free account</Link>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

"use client";

import Link from "next/link";
import { useState } from "react";
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
        <input
          id="instant-url"
          type="text"
          inputMode="url"
          autoComplete="off"
          placeholder="example.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="flex-1 rounded-md border border-slate-300 px-4 py-3 text-base"
        />
        <button type="submit" disabled={busy || url.trim() === ""} className="rounded-md bg-slate-900 px-6 py-3 font-semibold text-white disabled:opacity-50">
          {busy ? "Checking…" : "Check now"}
        </button>
      </form>

      <div role="status" aria-live="polite" className="mt-6">
        {error && <p className="rounded-md bg-red-50 p-4 text-red-800">{error}</p>}
        {result && (
          <section aria-label="Check result" className="rounded-lg border border-slate-200 p-6">
            <p className="text-sm text-slate-600">{result.target}</p>
            <p className="mt-1 text-4xl font-bold">{result.score}<span className="text-lg font-normal text-slate-500"> / 100</span></p>
            <p className="mt-1 text-slate-700">
              {result.total === 0 ? "No problems found in the TLS, headers and email checks." : `${result.total} thing${result.total === 1 ? "" : "s"} to fix in the TLS, headers and email checks.`}
            </p>
            {result.findings.length > 0 && (
              <ul className="mt-4 space-y-3">
                {result.findings.map((f) => (
                  <li key={f.title} className="rounded-md border border-slate-200 p-3">
                    <span className={`mr-2 rounded px-2 py-0.5 text-xs font-semibold uppercase ${SEVERITY_STYLE[f.severity] ?? "bg-slate-100"}`}>{f.severity}</span>
                    <span className="font-medium">{f.title}</span>
                    <p className="mt-1 text-sm text-slate-600">{f.detail}</p>
                  </li>
                ))}
              </ul>
            )}
            {result.hidden > 0 && <p className="mt-3 text-sm text-slate-600">and {result.hidden} more.</p>}
            <div className="mt-5 rounded-md bg-slate-50 p-4 text-sm text-slate-700">
              This is a light check of what any visitor can see. A full scan, after you verify you own the site, adds exposed files, vulnerable software, open ports and step-by-step fixes.{" "}
              <Link href="/signup" className="font-semibold underline">Create a free account</Link>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

"use client";

// "Request access" for an on-request document on a public security profile
// (src/lib/trustDocuments.ts). The owner decides; nothing is released here.
import { useState } from "react";
import { Button } from "@/components/ui/button";

const field = "mt-1 block w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-1.5 text-sm text-cybertext focus:border-neon focus:outline-hidden";

export function DocumentRequestForm({ slug, documentId, title }: { slug: string; documentId: string; title: string }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/profile/${slug}/documents/${documentId}/request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, ...(company.trim() ? { company } : {}), ...(reason.trim() ? { reason } : {}) }),
      });
      const body = (await res.json().catch(() => ({}))) as { message?: string; error?: string };
      if (!res.ok) throw new Error(body.error ?? "Couldn't send the request. Try again.");
      setDone(body.message ?? "Request sent.");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (done) return <p role="status" className="text-sm text-neon">{done}</p>;
  if (!open) {
    return (
      <Button size="sm" variant="secondary" onClick={() => setOpen(true)}>
        Request access{" "}
        <span className="sr-only">to {title}</span>
      </Button>
    );
  }
  return (
    <form onSubmit={submit} className="mt-2 grid gap-2 sm:grid-cols-2" aria-label={`Request ${title}`}>
      <label className="text-xs text-cybermuted">
        Your name
        <input required maxLength={120} value={name} onChange={(e) => setName(e.target.value)} className={field} />
      </label>
      <label className="text-xs text-cybermuted">
        Work email
        <input required type="email" maxLength={254} value={email} onChange={(e) => setEmail(e.target.value)} className={field} />
      </label>
      <label className="text-xs text-cybermuted">
        Company (optional)
        <input maxLength={120} value={company} onChange={(e) => setCompany(e.target.value)} className={field} />
      </label>
      <label className="text-xs text-cybermuted sm:col-span-2">
        Why you need it (optional)
        <textarea maxLength={1000} rows={2} value={reason} onChange={(e) => setReason(e.target.value)} className={field} />
      </label>
      <div className="flex flex-wrap items-center gap-2 sm:col-span-2">
        <Button size="sm" type="submit" disabled={busy}>
          {busy ? "Sending…" : "Send request"}
        </Button>
        <span className="text-xs text-cybermuted">The owner sees your name, email and reason, and decides.</span>
      </div>
      {error && <p role="alert" className="text-sm text-danger sm:col-span-2">{error}</p>}
    </form>
  );
}

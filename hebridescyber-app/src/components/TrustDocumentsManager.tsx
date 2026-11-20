"use client";

// Owner-only, on the scan report under the public profile toggle: the PDFs
// shown on this site's security profile (src/lib/trustDocuments.ts), and the
// requests for on-request ones. Hidden when the account can't use it (the
// list answers 403: below Pro, or not a signed-in session).
import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { DOCUMENT_KINDS, KIND_LABELS, formatSize, type DocumentKind } from "@/lib/trustDocumentKinds";

type Doc = { id: string; title: string; kind: DocumentKind; kindLabel: string; visibility: "public" | "on_request"; sizeBytes: number; uploadedAt: string };
type Req = { id: string; document_id: string; requester_name: string; requester_email: string; requester_company: string; reason: string; status: "pending" | "approved" | "declined"; created_at: string; download_count: number };

const MAX_BYTES = 5 * 1024 * 1024;
const field = "mt-1 block w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-1.5 text-sm text-cybertext focus:border-neon focus:outline-hidden";

function readAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error("Couldn't read that file."));
    reader.readAsDataURL(file);
  });
}

export function TrustDocumentsManager({ targetUrl, token }: { targetUrl: string; token: string }) {
  const [allowed, setAllowed] = useState<boolean | null>(null);
  const [docs, setDocs] = useState<Doc[]>([]);
  const [requests, setRequests] = useState<Req[]>([]);
  const [title, setTitle] = useState("");
  const [kind, setKind] = useState<DocumentKind>("cyber_essentials");
  const [visibility, setVisibility] = useState<"public" | "on_request">("on_request");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const auth = { Authorization: `Bearer ${token}` };

  const load = useCallback(async () => {
    try {
      const res = await fetch(`/api/trust-documents?targetUrl=${encodeURIComponent(targetUrl)}`, { headers: { Authorization: `Bearer ${token}` } });
      if (!res.ok) {
        setAllowed(false);
        return;
      }
      const body = (await res.json()) as { documents: Doc[]; requests: Req[] };
      setDocs(body.documents);
      setRequests(body.requests);
      setAllowed(true);
    } catch {
      setAllowed(false);
    }
  }, [targetUrl, token]);

  useEffect(() => {
    void load();
  }, [load]);

  if (!allowed) return null;

  async function upload(e: React.FormEvent) {
    e.preventDefault();
    if (!file) return;
    setMessage(null);
    if (file.type !== "application/pdf") return setMessage({ tone: "error", text: "Choose a PDF file." });
    if (file.size > MAX_BYTES) return setMessage({ tone: "error", text: "That file is over 5 MB." });
    setBusy(true);
    try {
      const dataUrl = await readAsDataUrl(file);
      const res = await fetch("/api/trust-documents", {
        method: "POST",
        headers: { ...auth, "Content-Type": "application/json" },
        body: JSON.stringify({ targetUrl, title: title.trim() || KIND_LABELS[kind], kind, visibility, dataUrl }),
      });
      const body = (await res.json().catch(() => ({}))) as { error?: string };
      if (!res.ok) throw new Error(body.error ?? "Couldn't upload it.");
      setTitle("");
      setFile(null);
      setMessage({ tone: "ok", text: "Added. It shows on your profile while the profile is published." });
      await load();
    } catch (err) {
      setMessage({ tone: "error", text: (err as Error).message });
    } finally {
      setBusy(false);
    }
  }

  async function setDocVisibility(id: string, next: Doc["visibility"]) {
    await fetch(`/api/trust-documents/${id}`, { method: "PATCH", headers: { ...auth, "Content-Type": "application/json" }, body: JSON.stringify({ visibility: next }) });
    await load();
  }

  async function remove(id: string) {
    if (!window.confirm("Remove this document? Any download links already sent stop working.")) return;
    await fetch(`/api/trust-documents/${id}`, { method: "DELETE", headers: auth });
    await load();
  }

  async function decide(id: string, decision: "approve" | "decline") {
    const res = await fetch(`/api/trust-documents/requests/${id}`, { method: "POST", headers: { ...auth, "Content-Type": "application/json" }, body: JSON.stringify({ decision }) });
    const body = (await res.json().catch(() => ({}))) as { emailed?: boolean; error?: string };
    setMessage(res.ok ? { tone: "ok", text: decision === "approve" ? (body.emailed ? "Approved: we've emailed them a download link." : "Approved, but the email didn't send. Try again later.") : "Declined: we've let them know." } : { tone: "error", text: body.error ?? "That didn't work." });
    await load();
  }

  const titleOf = (id: string) => docs.find((d) => d.id === id)?.title ?? "a removed document";
  const pending = requests.filter((r) => r.status === "pending");
  const decided = requests.filter((r) => r.status !== "pending").slice(0, 10);

  return (
    <Card className="print:hidden" aria-labelledby="trust-docs-heading">
      <CardHeader>
        <div>
          <CardTitle id="trust-docs-heading">profile documents</CardTitle>
          <CardDescription className="mt-1">
            PDFs shown on this site&apos;s public security profile, such as your Cyber Essentials certificate. Make one public, or available on request so you approve each person.
          </CardDescription>
        </div>
      </CardHeader>

      {pending.length > 0 && (
        <div className="mb-4">
          <p className="mb-2 text-xs uppercase tracking-wide text-cybermuted">Waiting for you</p>
          <ul className="space-y-2">
            {pending.map((r) => (
              <li key={r.id} className="rounded-lg border border-warning/40 bg-warning/5 p-3 text-sm">
                <p className="text-cybertext">
                  <b>{r.requester_name}</b>
                  {r.requester_company ? `, ${r.requester_company}` : ""} &lt;{r.requester_email}&gt; asked for <b>{titleOf(r.document_id)}</b>
                </p>
                {r.reason && <p className="mt-1 text-cybertext/80">&ldquo;{r.reason}&rdquo;</p>}
                <div className="mt-2 flex gap-2">
                  <Button size="sm" onClick={() => decide(r.id, "approve")}>
                    Approve{" "}
                    <span className="sr-only">request from {r.requester_name}</span>
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => decide(r.id, "decline")}>
                    Decline{" "}
                    <span className="sr-only">request from {r.requester_name}</span>
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {docs.length > 0 && (
        <ul className="mb-4 divide-y divide-cyberborder rounded-lg border border-cyberborder">
          {docs.map((d) => (
            <li key={d.id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm">
              <span className="min-w-0">
                <span className="text-cybertext">{d.title}</span>{" "}
                <span className="text-cybermuted">
                  · {d.kindLabel} · {formatSize(d.sizeBytes)}
                </span>
              </span>
              <span className="flex items-center gap-2">
                <label className="text-xs text-cybermuted">
                  <span className="sr-only">Who can download {d.title}</span>
                  <select value={d.visibility} onChange={(e) => setDocVisibility(d.id, e.target.value as Doc["visibility"])} className="rounded-md border border-cyberborder bg-cyberbg px-2 py-1 text-xs text-cybertext">
                    <option value="on_request">On request</option>
                    <option value="public">Anyone</option>
                  </select>
                </label>
                <Button size="sm" variant="ghost" onClick={() => remove(d.id)}>
                  Remove{" "}
                  <span className="sr-only">{d.title}</span>
                </Button>
              </span>
            </li>
          ))}
        </ul>
      )}

      <form onSubmit={upload} className="grid gap-2 sm:grid-cols-2" aria-label="Add a document">
        <label className="text-xs text-cybermuted">
          Kind
          <select value={kind} onChange={(e) => setKind(e.target.value as DocumentKind)} className={field}>
            {DOCUMENT_KINDS.map((k) => (
              <option key={k} value={k}>
                {KIND_LABELS[k]}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-cybermuted">
          Title (optional)
          <input value={title} maxLength={120} onChange={(e) => setTitle(e.target.value)} placeholder={KIND_LABELS[kind]} className={field} />
        </label>
        <label className="text-xs text-cybermuted">
          Who can download it
          <select value={visibility} onChange={(e) => setVisibility(e.target.value as "public" | "on_request")} className={field}>
            <option value="on_request">On request (you approve each person)</option>
            <option value="public">Anyone who views the profile</option>
          </select>
        </label>
        <label className="text-xs text-cybermuted">
          PDF, up to 5 MB
          <input type="file" accept="application/pdf" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="mt-1 block w-full text-sm text-cybertext" />
        </label>
        <div className="sm:col-span-2">
          <Button size="sm" type="submit" disabled={busy || !file}>
            {busy ? "Uploading…" : "Add document"}
          </Button>
        </div>
      </form>
      {message && (
        <p role={message.tone === "error" ? "alert" : "status"} className={`mt-3 text-sm ${message.tone === "error" ? "text-danger" : "text-cybertext"}`}>
          {message.text}
        </p>
      )}

      {decided.length > 0 && (
        <details className="mt-4 text-sm">
          <summary className="cursor-pointer text-cybermuted">Recent decisions</summary>
          <ul className="mt-2 space-y-1 text-cybertext/80">
            {decided.map((r) => (
              <li key={r.id}>
                {r.requester_email}: {titleOf(r.document_id)}, {r.status}
                {r.status === "approved" ? `, downloaded ${r.download_count} time${r.download_count === 1 ? "" : "s"}` : ""}
              </li>
            ))}
          </ul>
        </details>
      )}
      <p className="mt-3 text-xs text-cybermuted">Only share what you&apos;re happy for a customer or insurer to see. Download links from an approval work for 7 days and 5 downloads.</p>
    </Card>
  );
}

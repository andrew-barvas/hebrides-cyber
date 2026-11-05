"use client";

// "Request validation" on a serious finding: asks us to arrange a human-run,
// authorised test of this one finding. It records the request and tells us; it
// tests nothing (see src/pages/api/findings/validation-request.ts).
import { useId, useState } from "react";
import { NOTE_MAX } from "@/lib/validationEligibility";

type Status = "idle" | "form" | "sending" | "done" | "already" | "error";

export default function ValidationRequestButton({ scanId, token, checkId }: { scanId: string; token: string; checkId: string }) {
  const noteId = useId();
  const [status, setStatus] = useState<Status>("idle");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function send(e: React.FormEvent) {
    e.preventDefault();
    setStatus("sending");
    setError(null);
    try {
      const res = await fetch("/api/findings/validation-request", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ scanId, checkId, ...(note.trim() ? { note: note.trim() } : {}) }),
      });
      const body = await res.json().catch(() => ({}));
      if (res.status === 409) return setStatus("already");
      if (!res.ok) throw new Error(body.error ?? "Could not send the request");
      setStatus("done");
    } catch (err) {
      setError((err as Error).message);
      setStatus("error");
    }
  }

  if (status === "done") {
    return <p className="mt-3 text-xs text-cybermuted print:hidden">Request received. Nothing has been tested. We will contact you to agree the scope and get your written authorisation first.</p>;
  }
  if (status === "already") {
    return <p className="mt-3 text-xs text-cybermuted print:hidden">A validation request for this finding is already open.</p>;
  }
  if (status === "idle") {
    return (
      <button type="button" onClick={() => setStatus("form")} className="mt-3 text-xs font-semibold text-neon hover:text-neon/80 print:hidden">
        Request validation
      </button>
    );
  }
  return (
    <form onSubmit={send} className="mt-3 max-w-xl print:hidden">
      <p className="text-xs text-cybermuted">
        We will arrange for a person to test whether this can really be used against you. Nothing is tested until we agree the scope with you and you authorise it in writing.
      </p>
      <label htmlFor={noteId} className="mt-2 block text-xs font-medium">Anything we should know? (optional)</label>
      <textarea
        id={noteId}
        value={note}
        maxLength={NOTE_MAX}
        onChange={(e) => setNote(e.target.value)}
        rows={3}
        className="mt-1 w-full rounded border border-cyberborder bg-transparent p-2 text-xs"
      />
      {status === "error" && <p className="mt-1 text-xs text-red-400">{error}</p>}
      <div className="mt-2 flex gap-3">
        <button type="submit" disabled={status === "sending"} className="text-xs font-semibold text-neon hover:text-neon/80 disabled:opacity-50">
          {status === "sending" ? "Sending…" : "Send request"}
        </button>
        <button type="button" onClick={() => setStatus("idle")} className="text-xs text-cybermuted hover:underline">
          Cancel
        </button>
      </div>
    </form>
  );
}

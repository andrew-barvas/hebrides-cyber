"use client";

// Downloads the security evidence pack (GET /api/account/evidence-pack): Cyber
// Essentials readiness plus common insurance and supplier questionnaire
// answers, each saying where it comes from. Pro and above; the page shows it
// only then, and the route enforces it.

import { useState } from "react";
import { Button } from "@/components/ui/button";

export async function fetchEvidencePack(token: string): Promise<Blob> {
  const res = await fetch("/api/account/evidence-pack", { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { code?: string };
    if (body.code === "plan_required") throw new Error("The evidence pack is on the Pro plan and above.");
    throw new Error(res.status === 429 ? "Too many requests. Try again in a few minutes." : `The evidence pack could not be generated (${res.status}).`);
  }
  return res.blob();
}

export default function EvidencePackButton({ token }: { token: string | null }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function download() {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      const url = URL.createObjectURL(await fetchEvidencePack(token));
      const a = document.createElement("a");
      a.href = url;
      a.download = `security-evidence-pack-${new Date().toISOString().slice(0, 10)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-cyberborder bg-cyberpanel p-4">
      <div>
        <p className="text-sm font-semibold text-cybertext">Evidence pack for insurers and Cyber Essentials</p>
        <p className="text-xs text-cybermuted">One PDF answering the common insurance and supplier questions from your scans and your answers below, saying where each answer comes from.</p>
        {error && (
          <p role="alert" className="mt-1 text-xs text-danger">
            {error}
          </p>
        )}
      </div>
      <Button size="sm" onClick={download} disabled={busy || !token}>
        {busy ? "Preparing…" : "Download evidence pack"}
      </Button>
    </div>
  );
}

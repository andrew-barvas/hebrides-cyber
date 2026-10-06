"use client";

// Downloads the Agency portfolio report (GET /api/portfolio-report): every
// monitored site in one client-ready PDF. The route answers with the PDF
// bytes, or a JSON error with a code this turns into plain words.

import { useState } from "react";
import { Button } from "@/components/ui/button";

const MESSAGES: Record<string, string> = {
  plan_required: "The portfolio report is part of the Agency plan.",
  no_sites: "Add sites to monitoring first: the report covers every monitored site.",
};

export async function fetchPortfolioReport(token: string): Promise<Blob> {
  const res = await fetch("/api/portfolio-report", { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { code?: string };
    if (body.code && MESSAGES[body.code]) throw new Error(MESSAGES[body.code]);
    throw new Error(res.status === 429 ? "Too many report requests. Try again in a few minutes." : `The report could not be generated (${res.status}).`);
  }
  return res.blob();
}

export default function PortfolioReportButton({ token }: { token: string | null }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function download() {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      const blob = await fetchPortfolioReport(token);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `security-portfolio-${new Date().toISOString().slice(0, 10)}.pdf`;
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
        <p className="text-sm font-semibold text-cybertext">Portfolio report</p>
        <p className="text-xs text-cybermuted">Every monitored site in one PDF, worst first, with your branding.</p>
        {error && (
          <p role="alert" className="mt-1 text-xs text-danger">
            {error}
          </p>
        )}
      </div>
      <Button variant="secondary" size="sm" onClick={download} disabled={busy || !token}>
        {busy ? "Preparing…" : "↓ Portfolio PDF"}
      </Button>
    </div>
  );
}

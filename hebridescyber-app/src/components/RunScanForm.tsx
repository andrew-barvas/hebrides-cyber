"use client";

// The on-demand scan launcher: create → verify ownership → enqueue → poll.
// Moved out of dashboard/page.tsx unchanged apart from surfacing the API's
// error `code`, so the single most common first-scan failure (domain not
// verified yet) can link straight to the fix instead of just printing text.

import { useState } from "react";
import Link from "next/link";
import { getSession } from "@/lib/auth";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardTitle } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";

class ScanRequestError extends Error {
  constructor(message: string, readonly code?: string) {
    super(message);
  }
}

export default function RunScanForm({ onScanSettled }: { onScanSettled: () => void | Promise<void> }) {
  const [targetUrl, setTargetUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [error, setError] = useState<{ message: string; code?: string } | null>(null);

  async function startScan(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setScanMessage(null);
    setError(null);

    const session = await getSession();
    if (!session) {
      setError({ message: "Session expired — please sign in again." });
      setSubmitting(false);
      return;
    }

    try {
      const createRes = await fetch("/api/run-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.access_token}` },
        body: JSON.stringify({ targetUrl }),
      });
      const createBody = await createRes.json();
      if (!createRes.ok) throw new ScanRequestError(createBody.error ?? `run-scan create failed (${createRes.status})`, createBody.code);

      // Step 2 queues the scan rather than running it inline — see
      // src/pages/api/run-scan.ts and .github/workflows/on-demand-scan.yml
      // for why. "queued"/"running" responses mean poll again; only the
      // first call needs X-Scan-Token, since later polls hit the
      // already-"running" branch which skips ownership re-verification.
      const POLL_INTERVAL_MS = 4_000;
      const MAX_POLLS = 45; // ~3 minutes — comfortably above the on-demand workflow's expected runtime

      async function pollRunScan(withToken: boolean) {
        const res = await fetch("/api/run-scan", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${session!.access_token}`,
            ...(withToken ? { "X-Scan-Token": createBody.proofToken } : {}),
          },
          body: JSON.stringify({ scanId: createBody.scanId }),
        });
        const body = await res.json();
        if (!res.ok) throw new ScanRequestError(body.error ?? `run-scan failed (${res.status})`, body.code);
        return body;
      }

      let runBody = await pollRunScan(true);
      let polls = 0;
      while ((runBody.status === "queued" || runBody.status === "running") && polls < MAX_POLLS) {
        const progress = runBody.progress as { phase?: string; checks_completed?: string[]; checks_total?: number; current_check?: string; elapsed_ms?: number } | null;
        let phase: string;
        if (runBody.status === "queued") {
          phase = "Scan queued — waiting for a runner to pick it up…";
        } else if (progress?.current_check) {
          const pct = progress.checks_total ? Math.round(((progress.checks_completed?.length ?? 0) / progress.checks_total) * 100) : 0;
          const elapsed = progress.elapsed_ms ? `${Math.round(progress.elapsed_ms / 1000)}s` : "";
          phase = `Scanning (${pct}%)${elapsed ? ` · ${elapsed}` : ""} — ${progress.current_check}`;
        } else if (polls < 8) {
          phase = "Scanning — checking TLS, headers, DNS…";
        } else if (polls < 20) {
          phase = "Scanning — probing endpoints, detecting technologies…";
        } else {
          phase = "Scanning — running deep checks, almost done…";
        }
        setScanMessage(phase);
        await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
        runBody = await pollRunScan(false);
        polls++;
      }

      if (runBody.status === "queued" || runBody.status === "running") {
        setScanMessage(
          runBody.status === "queued"
            ? "Scan is queued and will be picked up shortly. Check back in a few minutes — the page will update automatically."
            : "Scan is still running — this can take a few minutes for larger sites. Check back shortly."
        );
      } else if (runBody.status === "failed" || runBody.ok === false) {
        throw new ScanRequestError(runBody.error ?? "Scan failed — try again.");
      } else {
        setScanMessage(`Scan complete — score ${runBody.score}/100.`);
        setTargetUrl("");
      }
      await onScanSettled();
    } catch (err) {
      setError({ message: (err as Error).message, code: err instanceof ScanRequestError ? err.code : undefined });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card id="run-a-scan" className="scroll-mt-6">
      <CardTitle className="mb-3">run a scan</CardTitle>
      <form onSubmit={startScan} className="flex flex-col gap-2 sm:flex-row sm:items-end">
        <div className="flex-1 space-y-1.5">
          <Label htmlFor="scan-target-url">Website URL</Label>
          <Input
            id="scan-target-url"
            type="url"
            required
            placeholder="https://your-site.com"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            aria-describedby="scan-target-help"
          />
        </div>
        <Button type="submit" disabled={submitting}>
          {submitting ? "Scanning…" : "Run scan"}
        </Button>
      </form>
      <p id="scan-target-help" className="mt-2 text-xs text-cybermuted">
        We scan only domains you&apos;ve{" "}
        <Link href="/dashboard/assets#domain-verification" className="text-neon hover:underline">
          verified you own
        </Link>
        . Results are private to your account and never shared or sold — see our{" "}
        <Link href="/privacy" className="text-neon hover:underline">
          privacy policy
        </Link>
        .
      </p>
      <div aria-live="polite">{scanMessage && <p className="mt-3 text-sm text-neon">{scanMessage}</p>}</div>
      {error && (
        <Alert variant="danger" className="mt-3" title={error.code === "domain_not_verified" ? "Verify this domain first" : undefined}>
          <p>{error.message}</p>
          {error.code === "domain_not_verified" && (
            <Link href="/dashboard/assets#domain-verification" className="mt-1 inline-block font-medium text-neon hover:underline">
              Go to domain verification →
            </Link>
          )}
        </Alert>
      )}
    </Card>
  );
}

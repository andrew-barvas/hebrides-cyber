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
import { scanTargetHint, useVerifiedDomains } from "@/lib/verifiedDomains";

class ScanRequestError extends Error {
  constructor(message: string, readonly code?: string) {
    super(message);
  }
}

// onScanUpdate refreshes the caller's scan list. It's called as soon as the
// scan row exists (so it appears in "Recent scans" without a manual refresh),
// on every poll (so its status badge goes pending → queued → running → done
// live), and once more when it settles.
export default function RunScanForm({ onScanUpdate }: { onScanUpdate: () => void | Promise<void> }) {
  const [targetUrl, setTargetUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [error, setError] = useState<{ message: string; code?: string } | null>(null);
  const verified = useVerifiedDomains();
  const hint = scanTargetHint(targetUrl, verified);

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

      // The scans row now exists (status "pending"). Surface it in the list
      // immediately — waiting until the poll loop ends is what made a new
      // scan look like it hadn't registered until a manual refresh.
      await onScanUpdate();

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
      // Only the enqueue response carries this; later polls omit it. Capture
      // it so the honest "under a minute" vs "next scheduled run" wording
      // stays put while the scan is queued.
      const queuedMessage: string | undefined = runBody.message;
      let polls = 0;
      while ((runBody.status === "queued" || runBody.status === "running") && polls < MAX_POLLS) {
        const progress = runBody.progress as { phase?: string; checks_completed?: string[]; checks_total?: number; current_check?: string; elapsed_ms?: number } | null;
        let phase: string;
        if (runBody.status === "queued") {
          // The captured message reflects whether a runner was actually
          // dispatched ("usually under a minute") or the on-demand trigger
          // was unavailable and it'll wait for the scheduled sweep — honest
          // either way, rather than always promising a minute.
          phase = queuedMessage ?? "Scan queued — waiting for a runner to pick it up…";
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
        // Keep the list's status badge in step with the poll (queued →
        // running → completed) instead of only updating when it all settles.
        await onScanUpdate();
        await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
        runBody = await pollRunScan(false);
        polls++;
      }

      if (runBody.status === "queued" || runBody.status === "running") {
        setScanMessage(
          runBody.status === "queued"
            ? `${queuedMessage ?? "Scan is queued."} It appears in Recent scans below and updates automatically — no need to refresh.`
            : "Scan is still running — this can take a few minutes for larger sites. It updates below automatically."
        );
      } else if (runBody.status === "failed" || runBody.ok === false) {
        throw new ScanRequestError(runBody.error ?? "Scan failed — try again.");
      } else {
        setScanMessage(`Scan complete — score ${runBody.score}/100.`);
        setTargetUrl("");
      }
      await onScanUpdate();
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
      {hint && !error && (
        <p role="status" className="mt-2 text-xs text-warning">
          {hint.host} isn&apos;t verified on your account yet, so it can&apos;t be scanned.
          {hint.verifiedAlternative && <> You&apos;ve verified {hint.verifiedAlternative}: scan that address instead, or verify {hint.host} as well.</>}{" "}
          <Link href="/dashboard/assets#domain-verification" className="font-medium text-neon hover:underline">
            Verify {hint.host} →
          </Link>
        </p>
      )}
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

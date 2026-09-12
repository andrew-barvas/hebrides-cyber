// Signed webhook delivery — fires when a scan completes, POSTing the same
// report shape GET /api/v1/scans/{id} returns (see src/lib/scanReport.ts) so
// customers see one consistent contract whether they poll or get pushed to.
//
// The job queue that exists (sql/migrations/008_scan_jobs.sql, worked by
// GitHub Actions runners — see scanExecution.ts) is for scheduled/bulk
// scanning, not webhook delivery itself: delivery still happens inline, in
// the same process that just finished running the scan, whether that's the
// synchronous dashboard path or a queue worker. That rules out the
// multi-hour backoff schedule a dedicated delivery queue would allow: one
// immediate attempt, one quick retry, then give up and record the failure.
// The caller already waited for the whole scan to run: a few more seconds
// for webhook fan-out is acceptable, an unbounded retry loop blocking the
// response is not.
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { ScanReport } from "./scanReport";
import { validateNoSsrf } from "./ownership";

const SECRET_BYTES = 24;
const DELIVERY_TIMEOUT_MS = 8_000;
const RETRY_DELAY_MS = 2_000;
const DISABLE_AFTER_FAILURES = 20;

export function generateWebhookSecret(): string {
  return `whsec_${randomBytes(SECRET_BYTES).toString("base64url")}`;
}

export function signPayload(secret: string, body: string, timestampSeconds: number): string {
  return createHmac("sha256", secret).update(`${timestampSeconds}.${body}`).digest("hex");
}

export function buildSignatureHeader(secret: string, body: string, timestampSeconds: number): string {
  return `t=${timestampSeconds},v1=${signPayload(secret, body, timestampSeconds)}`;
}

/**
 * Verifies a `hc-signature` header against a raw body. Not called by any
 * production code path here — this project only sends webhooks, it doesn't
 * receive any — but it exists so the verification example in docs/API.md is
 * an actual tested implementation rather than untested pseudocode, and so a
 * future receiving endpoint (if this product ever consumes its own webhooks)
 * has a correct implementation to start from.
 */
export function verifySignatureHeader(
  secret: string,
  body: string,
  header: string,
  toleranceSeconds = 300
): boolean {
  const match = /^t=(\d+),v1=([0-9a-f]+)$/.exec(header);
  if (!match) return false;
  const [, tsStr, providedSig] = match;
  const timestamp = Number(tsStr);
  if (!Number.isFinite(timestamp) || Math.abs(Date.now() / 1000 - timestamp) > toleranceSeconds) return false;

  const expected = signPayload(secret, body, timestamp);
  const a = Buffer.from(expected);
  const b = Buffer.from(providedSig);
  return a.length === b.length && timingSafeEqual(a, b);
}

export type WebhookRow = {
  id: string;
  url: string;
  secret: string;
  failure_count: number;
};

async function attemptDelivery(url: string, body: string, signatureHeader: string): Promise<boolean> {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", "hc-signature": signatureHeader },
      body,
      signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
    });
    return res.ok;
  } catch {
    return false;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Delivers to one webhook: one attempt, one retry on failure, then records
 * the outcome. Never throws — a delivery failure is data (failure_count),
 * not an exception the caller needs to handle.
 */
async function deliverOne(supabaseAdmin: SupabaseClient, webhook: WebhookRow, body: string): Promise<void> {
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = buildSignatureHeader(webhook.secret, body, timestamp);

  // Re-validated on every delivery, not just at registration (src/pages/api/
  // webhooks.ts also checks at save time, but that result can go stale —
  // DNS can legitimately repoint at internal infrastructure between
  // registration and a scan firing weeks or months later). This is the
  // single choke point every outbound delivery passes through regardless of
  // how the row was created, which is what makes it the check that actually
  // matters. One check per delivery, not per retry attempt — a target that
  // fails SSRF validation won't pass on a second try 2 seconds later, so
  // there's nothing to retry.
  let ok: boolean;
  try {
    await validateNoSsrf(webhook.url);
    ok = await attemptDelivery(webhook.url, body, signature);
    if (!ok) {
      await sleep(RETRY_DELAY_MS);
      ok = await attemptDelivery(webhook.url, body, signature);
    }
  } catch (err) {
    console.error(`[webhooks] refusing to deliver to webhook ${webhook.id}:`, (err as Error).message);
    ok = false;
  }

  if (ok) {
    await supabaseAdmin
      .from("webhooks")
      .update({ failure_count: 0, last_success_at: new Date().toISOString() })
      .eq("id", webhook.id);
    return;
  }

  const nextFailureCount = webhook.failure_count + 1;
  const update: Record<string, unknown> = {
    failure_count: nextFailureCount,
    last_failure_at: new Date().toISOString(),
  };
  // Auto-disable rather than retry forever against a dead or wrong URL — a
  // customer who registers a typo'd endpoint shouldn't cost every future scan
  // an extra 10 seconds indefinitely.
  if (nextFailureCount >= DISABLE_AFTER_FAILURES) {
    update.disabled_at = new Date().toISOString();
  }
  await supabaseAdmin.from("webhooks").update(update).eq("id", webhook.id);
}

/**
 * Looks up the owner's active webhooks and delivers the scan-completed event
 * to all of them in parallel. Call this after a scan's status is already
 * 'completed' and its scan_results row is already written — the report this
 * sends IS that row, so calling it earlier would send incomplete data.
 *
 * Swallows all errors internally (including the initial webhooks lookup) —
 * webhook delivery must never be able to fail the scan request that triggered
 * it. Call this without awaiting if the caller doesn't want to add the
 * delivery time to its own response latency; awaiting it is also safe.
 */
export async function dispatchScanCompletedWebhooks(
  supabaseAdmin: SupabaseClient,
  ownerId: string,
  report: ScanReport
): Promise<void> {
  try {
    const { data: webhooks } = await supabaseAdmin
      .from("webhooks")
      .select("id, url, secret, failure_count")
      .eq("owner", ownerId)
      .is("disabled_at", null);

    if (!webhooks || webhooks.length === 0) return;

    const body = JSON.stringify({
      event: "scan.completed",
      sent_at: new Date().toISOString(),
      data: report,
    });

    await Promise.allSettled(
      (webhooks as WebhookRow[]).map((webhook) => deliverOne(supabaseAdmin, webhook, body))
    );
  } catch (err) {
    console.error("[webhooks] dispatch failed:", (err as Error).message);
  }
}

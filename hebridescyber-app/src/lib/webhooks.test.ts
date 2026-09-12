import { describe, it, expect, vi, afterEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { ScanReport } from "./scanReport";

// validateNoSsrf (src/lib/ownership.ts) resolves the target hostname via
// real DNS — mocked here the same way src/lib/scanners/dns.test.ts mocks
// node:dns/promises, so these tests are deterministic and don't depend on
// a live network call. The private-IP/metadata-IP cases below use bare IP
// literals instead, which validateNoSsrf checks without any DNS lookup at
// all, so they don't need this mock to be meaningful.
const { resolve4Mock, resolve6Mock } = vi.hoisted(() => ({
  resolve4Mock: vi.fn(),
  resolve6Mock: vi.fn(),
}));
// Static factory (not `importOriginal`), and with a `default` export
// mirroring the named ones — see src/lib/scanners/dns.test.ts's identical
// mock for why both of those specifics matter (an importOriginal-based
// mock silently never intercepts the instance ownership.ts imports).
vi.mock("node:dns/promises", () => {
  const exports = { resolve4: resolve4Mock, resolve6: resolve6Mock };
  return { ...exports, default: exports };
});

import { dispatchScanCompletedWebhooks } from "./webhooks";

function report(): ScanReport {
  return {
    scan_id: "scan-1",
    target_url: "https://example.com",
    status: "completed",
    created_at: "2026-03-01T00:00:00Z",
    score: 80,
    findings: [],
    fixed_findings: [],
    critical_paths: [],
  } as unknown as ScanReport;
}

function makeSupabase(webhookRows: unknown[]) {
  const updateCalls: Array<Record<string, unknown>> = [];
  const supabase = {
    from: () => ({
      select: () => ({
        eq: () => ({
          is: () => Promise.resolve({ data: webhookRows, error: null }),
        }),
      }),
      update: (patch: Record<string, unknown>) => {
        updateCalls.push(patch);
        return { eq: () => Promise.resolve({ data: null, error: null }) };
      },
    }),
  };
  return { supabase: supabase as unknown as SupabaseClient, updateCalls };
}

describe("dispatchScanCompletedWebhooks", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("delivers to a webhook whose URL resolves to a public address", async () => {
    resolve4Mock.mockResolvedValue(["93.184.216.34"]);
    resolve6Mock.mockRejectedValue(new Error("ENODATA"));
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    global.fetch = fetchMock;

    const { supabase, updateCalls } = makeSupabase([
      { id: "wh-1", url: "https://example.com/hook", secret: "whsec_x", failure_count: 0 },
    ]);

    await dispatchScanCompletedWebhooks(supabase, "owner-1", report());

    expect(fetchMock).toHaveBeenCalledWith("https://example.com/hook", expect.any(Object));
    expect(updateCalls[0]).toMatchObject({ failure_count: 0 });
  });

  // Regression guard: this is the real SSRF fix for the generic
  // customer-webhook path — unlike the Slack/Teams vendor integrations
  // (webhookUrlValidation.ts's fixed allowlist), a webhook URL here is
  // genuinely arbitrary owner-controlled infrastructure, so the check has
  // to be validateNoSsrf's private-IP/metadata-endpoint block, re-run on
  // every delivery (not just at registration) since DNS can legitimately
  // repoint between save time and a scan firing weeks later.
  it("never calls fetch for a webhook URL that resolves to a private/metadata IP", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock;

    const { supabase, updateCalls } = makeSupabase([
      { id: "wh-1", url: "https://169.254.169.254/latest/meta-data/", secret: "whsec_x", failure_count: 0 },
    ]);

    await dispatchScanCompletedWebhooks(supabase, "owner-1", report());

    expect(fetchMock).not.toHaveBeenCalled();
    // Still recorded as a failed delivery, same accounting as a real network failure.
    expect(updateCalls[0]).toMatchObject({ failure_count: 1 });
  });

  it("never throws out of dispatch even when every delivery is SSRF-blocked", async () => {
    global.fetch = vi.fn();
    const { supabase } = makeSupabase([{ id: "wh-1", url: "http://127.0.0.1/hook", secret: "whsec_x", failure_count: 0 }]);

    await expect(dispatchScanCompletedWebhooks(supabase, "owner-1", report())).resolves.toBeUndefined();
  });
});

// Wiring test for executeScan: drives a "safe" scan end to end with every
// check and notifier stubbed, to pin down what runs, in what order, and
// that nothing after completion can turn a completed scan into a failure.
import { describe, it, expect, vi, beforeEach } from "vitest";

const { calls, attackSurfaceMock, lookalikeMock, record } = vi.hoisted(() => {
  const calls: string[] = [];
  return {
    calls,
    attackSurfaceMock: vi.fn(),
    lookalikeMock: vi.fn(),
    record: (name: string, value: unknown = undefined) => vi.fn(async () => (calls.push(name), value)),
  };
});

vi.mock("./scanners", () => ({
  runAllChecks: vi.fn(async () => (calls.push("runAllChecks"), { fingerprint: { status: "error", note: "stub" }, recon: { status: "checked", ip: null, shodan: null, subdomains: [] } })),
  summariseResults: vi.fn(() => ({ findings: [{ checkId: "headers.hsts", severity: "medium", title: "No HSTS", detail: "", remediation: "" }] })),
  scoreFromFindings: vi.fn(() => 88),
  generateAiSummary: vi.fn(async () => "summary"),
  enrichFindingsWithCvss: vi.fn(async () => {}),
  enrichFindingsWithThreatIntel: vi.fn(async () => {}),
}));
vi.mock("./assetInventory", () => ({ syncAssetInventory: record("syncAssetInventory") }));
vi.mock("./attackSurfaceMonitor", async (orig) => ({ ...(await orig<typeof import("./attackSurfaceMonitor")>()), sendAttackSurfaceAlerts: attackSurfaceMock }));
vi.mock("./lookalikeDomainMonitor", async (orig) => ({ ...(await orig<typeof import("./lookalikeDomainMonitor")>()), sendLookalikeDomainAlerts: lookalikeMock }));
vi.mock("./easmDiscovery", () => ({ runEasmDiscovery: record("runEasmDiscovery") }));
vi.mock("./findingLifecycle", async (orig) => ({ ...(await orig<typeof import("./findingLifecycle")>()), syncFindingLifecycle: record("syncFindingLifecycle", null) }));
vi.mock("./slaAlerts", () => ({ sendSlaAlerts: record("sendSlaAlerts") }));
vi.mock("./webhooks", () => ({ dispatchScanCompletedWebhooks: record("dispatchScanCompletedWebhooks") }));
vi.mock("./scanAlerts", () => ({ sendCriticalAlertEmail: record("sendCriticalAlertEmail") }));
vi.mock("./scanCompletionEmail", () => ({ sendScanCompletionEmail: record("sendScanCompletionEmail") }));
vi.mock("./ticketAutoClose", () => ({ autoCloseFixedFindingTickets: record("autoCloseFixedFindingTickets") }));
vi.mock("./oncallAlerts", () => ({ triggerOncallAlerts: record("triggerOncallAlerts"), resolveOncallAlerts: record("resolveOncallAlerts") }));
vi.mock("./siemIntegration", () => ({ forwardToSiem: record("forwardToSiem") }));
vi.mock("./audit", () => ({ logAuditEvent: vi.fn(async (_db: unknown, e: { action: string }) => calls.push(`audit:${e.action}`)) }));

import { executeScan } from "./scanExecution";

/** Accepts any query chain and answers { data: null, error: null }; records writes to scans. */
function fakeSupabase() {
  const scanUpdates: Array<Record<string, unknown>> = [];
  const client = {
    from: (table: string) => {
      const b: Record<string, unknown> = {};
      for (const m of ["select", "eq", "neq", "lt", "gte", "in", "is", "order", "limit", "delete", "insert", "upsert", "ilike"]) b[m] = () => b;
      b.update = (values: Record<string, unknown>) => {
        if (table === "scans") scanUpdates.push(values);
        return b;
      };
      b.maybeSingle = () => Promise.resolve({ data: null, error: null });
      b.single = b.maybeSingle;
      b.then = (resolve: (v: unknown) => unknown, reject?: (e: unknown) => unknown) => Promise.resolve({ data: null, error: null }).then(resolve, reject);
      return b;
    },
  };
  return { client: client as never, scanUpdates };
}

beforeEach(() => {
  calls.length = 0;
  attackSurfaceMock.mockReset();
  attackSurfaceMock.mockImplementation(async () => {
    calls.push("sendAttackSurfaceAlerts");
  });
  lookalikeMock.mockReset();
  lookalikeMock.mockImplementation(async () => {
    calls.push("sendLookalikeDomainAlerts");
  });
});

describe("executeScan wiring", () => {
  it("completes, then records the inventory before the attack-surface alerts, which run last", async () => {
    const { client, scanUpdates } = fakeSupabase();
    const result = await executeScan(client, "scan-1", "owner-1", "https://shop.example");

    expect(result).toMatchObject({ ok: true, score: 88, summary: "summary" });
    expect(scanUpdates.some((u) => u.status === "completed")).toBe(true);
    // This scan's crt.sh data goes along: it is the evidence a hostname is new.
    expect(attackSurfaceMock).toHaveBeenCalledWith(client, "owner-1", "scan-1", "https://shop.example", { status: "checked", ip: null, shodan: null, subdomains: [] });
    const after = calls.slice(calls.indexOf("audit:scan.completed"));
    expect(after).toEqual([
      "audit:scan.completed",
      "syncAssetInventory",
      "runEasmDiscovery",
      "syncFindingLifecycle",
      "dispatchScanCompletedWebhooks",
      "sendCriticalAlertEmail",
      "sendScanCompletionEmail",
      "autoCloseFixedFindingTickets",
      "triggerOncallAlerts",
      "resolveOncallAlerts",
      "forwardToSiem",
      "sendAttackSurfaceAlerts",
      "sendLookalikeDomainAlerts",
    ]);
  });

  it("keeps the scan completed even if the attack-surface alerts throw", async () => {
    attackSurfaceMock.mockRejectedValue(new Error("boom"));
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const { client, scanUpdates } = fakeSupabase();

    const result = await executeScan(client, "scan-2", "owner-1", "https://shop.example");

    expect(result.ok).toBe(true);
    expect(scanUpdates.some((u) => u.status === "failed")).toBe(false);
    expect(calls).toContain("forwardToSiem");
    expect(errors).toHaveBeenCalledWith(expect.stringContaining("post-completion notifications failed for scan scan-2"), "boom");
    errors.mockRestore();
  });

  it("never reaches the alerts when the scan itself fails", async () => {
    const { runAllChecks } = await import("./scanners");
    vi.mocked(runAllChecks).mockRejectedValueOnce(new Error("checks crashed"));
    const { client, scanUpdates } = fakeSupabase();

    const result = await executeScan(client, "scan-3", "owner-1", "https://shop.example");

    expect(result).toEqual({ ok: false, error: "checks crashed" });
    expect(scanUpdates.some((u) => u.status === "failed")).toBe(true);
    expect(attackSurfaceMock).not.toHaveBeenCalled();
    expect(lookalikeMock).not.toHaveBeenCalled();
    expect(calls).not.toContain("syncAssetInventory");
  });
});

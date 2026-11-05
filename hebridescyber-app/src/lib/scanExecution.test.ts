// Wiring test for executeScan: drives a "safe" scan end to end with every
// check and notifier stubbed, to pin down what runs, in what order, and
// that nothing after completion can turn a completed scan into a failure.
import { describe, it, expect, vi, beforeEach } from "vitest";

const { calls, attackSurfaceMock, lookalikeMock, whatwafMock, record, engineFault } = vi.hoisted(() => {
  const calls: string[] = [];
  return {
    calls,
    engineFault: { throws: false },
    attackSurfaceMock: vi.fn(),
    lookalikeMock: vi.fn(),
    whatwafMock: vi.fn(),
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
vi.mock("../worker/tools/whatwaf", () => ({ runWhatWaf: whatwafMock }));
vi.mock("./exploitability", async (orig) => {
  const actual = await orig<typeof import("./exploitability")>();
  return {
    ...actual,
    assessFindings: (...args: Parameters<typeof actual.assessFindings>) => {
      if (engineFault.throws) throw new Error("engine fault");
      return actual.assessFindings(...args);
    },
  };
});

import { executeScan } from "./scanExecution";
import { scoreFromFindings, summariseResults } from "./scanners";
import * as findingTriage from "./findingTriage";
import { canDetectFromResults } from "./findingLifecycle";
import { EXTENDED_TOOL_NAMES } from "./scanProfiles";

/** Accepts any query chain and answers { data: null, error: null }; records writes to scans and scan_results. */
function fakeSupabase() {
  const scanUpdates: Array<Record<string, unknown>> = [];
  const resultInserts: Array<{ results: Record<string, unknown> }> = [];
  const assessmentInserts: Array<Record<string, unknown>> = [];
  const client = {
    from: (table: string) => {
      const b: Record<string, unknown> = {};
      for (const m of ["select", "eq", "neq", "lt", "gte", "in", "is", "order", "limit", "delete", "upsert", "ilike"]) b[m] = () => b;
      b.update = (values: Record<string, unknown>) => {
        if (table === "scans") scanUpdates.push(values);
        return b;
      };
      b.insert = (values: { results: Record<string, unknown> }) => {
        if (table === "scan_results") resultInserts.push(values);
        if (table === "exploitability_assessments") assessmentInserts.push(...(values as unknown as Array<Record<string, unknown>>));
        return b;
      };
      b.maybeSingle = () => Promise.resolve({ data: null, error: null });
      b.single = b.maybeSingle;
      b.then = (resolve: (v: unknown) => unknown, reject?: (e: unknown) => unknown) => Promise.resolve({ data: null, error: null }).then(resolve, reject);
      return b;
    },
  };
  return { client: client as never, scanUpdates, resultInserts, assessmentInserts };
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

describe("executeScan exploitability pass", () => {
  type Stored = { checkId?: string; severity: string; exploitability?: { band: string } };
  const EXPOSED = "exposure.exposed-file:/.env";
  const reported = () => [
    { checkId: EXPOSED, severity: "critical", title: "Exposed .env", detail: "", remediation: "", metadata: { proofOfExploit: { confirmed: true } } },
    { checkId: "headers.hsts", severity: "medium", title: "No HSTS", detail: "", remediation: "" },
  ];
  const findingsOf = (inserts: Array<{ results: Record<string, unknown> }>) => inserts[0].results.findings as Stored[];

  it("stores the summary on assessed findings and a row per assessment, with severity untouched", async () => {
    vi.mocked(summariseResults).mockReturnValueOnce({ findings: reported() } as never);
    const { client, resultInserts, assessmentInserts } = fakeSupabase();
    const result = await executeScan(client, "scan-x", "owner-1", "https://shop.example", { confirmExploits: false });

    expect(result).toMatchObject({ ok: true, score: 88 });
    const [exposed, hsts] = findingsOf(resultInserts);
    expect(exposed.severity).toBe("critical");
    expect(exposed.exploitability).toBeDefined();
    expect(hsts.exploitability).toBeUndefined();
    expect(assessmentInserts).toHaveLength(1);
    expect(assessmentInserts[0]).toMatchObject({ owner: "owner-1", scan_id: "scan-x", host: "shop.example", check_id: EXPOSED });
  });

  it("runs after the score, so the score never sees it", async () => {
    vi.mocked(summariseResults).mockReturnValueOnce({ findings: reported() } as never);
    const seen: boolean[] = [];
    vi.mocked(scoreFromFindings).mockImplementationOnce((findings) => {
      seen.push(...findings.map((f) => "exploitability" in f));
      return 88;
    });
    const { client, resultInserts } = fakeSupabase();
    await executeScan(client, "scan-x", "owner-1", "https://shop.example", { confirmExploits: false });

    expect(seen).toEqual([false, false]);
    expect(findingsOf(resultInserts)[0].exploitability).toBeDefined();
  });

  it("completes the scan with the same score and no assessments if the engine throws", async () => {
    vi.mocked(summariseResults).mockReturnValueOnce({ findings: reported() } as never);
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    engineFault.throws = true;
    try {
      const { client, scanUpdates, resultInserts, assessmentInserts } = fakeSupabase();
      const result = await executeScan(client, "scan-x", "owner-1", "https://shop.example", { confirmExploits: false });

      expect(result).toMatchObject({ ok: true, score: 88 });
      expect(scanUpdates.some((u) => u.status === "completed")).toBe(true);
      expect(findingsOf(resultInserts)[0].exploitability).toBeUndefined();
      expect(assessmentInserts).toEqual([]);
    } finally {
      engineFault.throws = false;
      errors.mockRestore();
    }
  });

  it("never stores `reproduced` under the exposure profile", async () => {
    vi.mocked(summariseResults).mockReturnValueOnce({ findings: reported() } as never);
    const { client, resultInserts, assessmentInserts } = fakeSupabase();
    const toolOverrides = Object.fromEntries(EXTENDED_TOOL_NAMES.map((n) => [n, false]));
    await executeScan(client, "scan-x", "owner-1", "https://shop.example", { profile: "exposure", toolOverrides });

    expect(findingsOf(resultInserts)[0].exploitability?.band).toBe("likely");
    expect(assessmentInserts[0].band).toBe("likely");
  });

  it("gives an active false positive no assessment, but keeps it stored", async () => {
    vi.mocked(summariseResults).mockReturnValueOnce({ findings: reported() } as never);
    const index = findingTriage.buildTriageIndex(
      [{ id: "t1", owner: "owner-1", target_host: "shop.example", check_id: EXPOSED, state: "false_positive", reason: "a test fixture", expires_at: null, created_by: null, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" }],
      new Date(),
    );
    const load = vi.spyOn(findingTriage, "loadTriageIndexForTarget").mockResolvedValueOnce({ host: "shop.example", index });
    try {
      const { client, resultInserts, assessmentInserts } = fakeSupabase();
      await executeScan(client, "scan-x", "owner-1", "https://shop.example", { confirmExploits: false });

      const [exposed] = findingsOf(resultInserts);
      expect(exposed.checkId).toBe(EXPOSED);
      expect(exposed.exploitability).toBeUndefined();
      expect(assessmentInserts).toEqual([]);
    } finally {
      load.mockRestore();
    }
  });
});

describe("executeScan extended findings: whatwaf", () => {
  /** A scheduled-style scan with whatwaf the only extended tool on; returns what was stored. */
  async function scanWithWhatWaf(result: unknown) {
    whatwafMock.mockReset();
    whatwafMock.mockResolvedValue(result);
    const { client, resultInserts } = fakeSupabase();
    const toolOverrides = Object.fromEntries(EXTENDED_TOOL_NAMES.map((n) => [n, n === "whatwaf"]));
    const scan = await executeScan(client, "scan-waf", "owner-1", "https://shop.example", { profile: "full", toolOverrides, confirmExploits: false });
    expect(scan.ok).toBe(true);
    expect(whatwafMock).toHaveBeenCalledWith("https://shop.example");
    const stored = resultInserts[0].results;
    const findings = (stored.findings as Array<{ checkId?: string; severity: string; detail: string }>).filter((f) => f.checkId?.startsWith("whatwaf."));
    return { stored, findings, canDetect: canDetectFromResults(stored) };
  }

  it("emits no finding for an errored run, and doesn't count it as covering last scan's whatwaf findings", async () => {
    const { stored, findings, canDetect } = await scanWithWhatWaf({ status: "error", note: "whatwaf output had no verdict line, so it says nothing about a WAF" });
    expect(findings).toEqual([]);
    expect((stored.extended as Record<string, { status: string }>).whatwaf.status).toBe("error");
    expect(canDetect({ checkId: "whatwaf.no-waf" })).toBe(false);
    expect(canDetect({ checkId: "whatwaf.waf-detected" })).toBe(false);
  });

  it("emits a medium whatwaf.no-waf, quoting the evidence, only for a positive no-WAF report", async () => {
    const evidence = 'WhatWaf reported: "[SUCCESS] no protection identified on target".';
    const { findings, canDetect } = await scanWithWhatWaf({ status: "completed", waf: null, vendor: null, evidence });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ checkId: "whatwaf.no-waf", severity: "medium", detail: expect.stringContaining(evidence) });
    expect(canDetect({ checkId: "whatwaf.waf-detected" })).toBe(true);
  });

  it("emits an info whatwaf.waf-detected with no confidence figure when a WAF is found", async () => {
    const { findings } = await scanWithWhatWaf({ status: "completed", waf: "Cloudflare", vendor: null, evidence: `WhatWaf reported: "[FIREWALL] detected website protection identified as 'Cloudflare'".` });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ checkId: "whatwaf.waf-detected", severity: "info" });
    expect(findings[0].detail).not.toMatch(/confidence/i);
  });
});

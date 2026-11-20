// Wiring test for executeScan: drives a "safe" scan end to end with every
// check and notifier stubbed, to pin down what runs, in what order, and
// that nothing after completion can turn a completed scan into a failure.
import { describe, it, expect, vi, beforeEach } from "vitest";

const { calls, attackSurfaceMock, lookalikeMock, whatwafMock, customChecksMock, nucleiMock, record, engineFault, posture, resolveAuthMock, proofMock, reportMock, slackMock, teamsMock } = vi.hoisted(() => {
  const calls: string[] = [];
  return {
    calls,
    posture: { cloud: vi.fn(), prowler: vi.fn(), m365: vi.fn(), workspace: vi.fn() },
    resolveAuthMock: vi.fn(),
    proofMock: vi.fn(),
    reportMock: vi.fn(),
    slackMock: vi.fn(async () => {}),
    teamsMock: vi.fn(async () => {}),
    engineFault: { throws: false },
    attackSurfaceMock: vi.fn(),
    lookalikeMock: vi.fn(),
    whatwafMock: vi.fn(),
    customChecksMock: vi.fn(async () => []),
    nucleiMock: vi.fn(async () => ({ status: "completed", findings: [] })),
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
vi.mock("./customChecks", () => ({ runCustomChecksForOwner: customChecksMock }));
vi.mock("../worker/tools/nuclei", () => ({ runNuclei: nucleiMock }));
vi.mock("./scanners/cloudPosture", () => ({ runCloudPostureChecks: posture.cloud }));
vi.mock("../worker/tools/prowlerIam", () => ({ runProwlerIam: posture.prowler }));
vi.mock("./scanners/m365Posture", () => ({ runM365PostureChecks: posture.m365 }));
vi.mock("./scanners/workspacePosture", () => ({ runWorkspacePostureChecks: posture.workspace }));
vi.mock("./scanners/authenticatedCheck", async (orig) => {
  const actual = await orig<typeof import("./scanners/authenticatedCheck")>();
  resolveAuthMock.mockImplementation(actual.resolveAuthCredential);
  return { ...actual, resolveAuthCredential: resolveAuthMock };
});
vi.mock("./scanners/proofOfExploit", async (orig) => {
  const actual = await orig<typeof import("./scanners/proofOfExploit")>();
  proofMock.mockImplementation(actual.enrichWithProofOfExploit);
  return { ...actual, enrichWithProofOfExploit: proofMock };
});
vi.mock("./scanReport", async (orig) => {
  const actual = await orig<typeof import("./scanReport")>();
  reportMock.mockImplementation(actual.buildScanReport);
  return { ...actual, buildScanReport: reportMock };
});
vi.mock("./slack", () => ({ sendSlackAlert: slackMock }));
vi.mock("./msTeams", () => ({ sendTeamsAlert: teamsMock }));
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

import { executeScan, confirmExploitable } from "./scanExecution";
import { scoreFromFindings, summariseResults } from "./scanners";
import * as findingTriage from "./findingTriage";
import { canDetectFromResults } from "./findingLifecycle";
import { EXTENDED_TOOL_NAMES } from "./scanProfiles";

/**
 * Accepts any query chain and answers { data: null, error: null }; records writes to scans and scan_results.
 * `rows` gives a table's maybeSingle answer; reading `failTable` throws.
 */
function fakeSupabase(opts: { rows?: Record<string, unknown>; failTable?: string } = {}) {
  const scanUpdates: Array<Record<string, unknown>> = [];
  const resultInserts: Array<{ results: Record<string, unknown> }> = [];
  const assessmentInserts: Array<Record<string, unknown>> = [];
  const client = {
    from: (table: string) => {
      if (table === opts.failTable) throw new Error(`relation "${table}" does not exist`);
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
      b.maybeSingle = () => Promise.resolve({ data: opts.rows?.[table] ?? null, error: null });
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
  type Stored = { checkId?: string; severity: string; exploitabilityAssessment?: { band: string; nonIntrusive: boolean } };
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
    expect(exposed.exploitabilityAssessment).toBeDefined();
    expect(hsts.exploitabilityAssessment).toBeUndefined();
    expect(assessmentInserts).toHaveLength(1);
    expect(assessmentInserts[0]).toMatchObject({ owner: "owner-1", scan_id: "scan-x", host: "shop.example", check_id: EXPOSED });
  });

  it("runs after the score, so the score never sees it", async () => {
    vi.mocked(summariseResults).mockReturnValueOnce({ findings: reported() } as never);
    const seen: boolean[] = [];
    vi.mocked(scoreFromFindings).mockImplementationOnce((findings) => {
      seen.push(...findings.map((f) => "exploitabilityAssessment" in f));
      return 88;
    });
    const { client, resultInserts } = fakeSupabase();
    await executeScan(client, "scan-x", "owner-1", "https://shop.example", { confirmExploits: false });

    expect(seen).toEqual([false, false]);
    expect(findingsOf(resultInserts)[0].exploitabilityAssessment).toBeDefined();
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
      expect(findingsOf(resultInserts)[0].exploitabilityAssessment).toBeUndefined();
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

    const [exposed] = findingsOf(resultInserts);
    expect(exposed.exploitabilityAssessment).toMatchObject({ band: "likely", nonIntrusive: true });
    expect(assessmentInserts[0]).toMatchObject({ band: "likely", non_intrusive: true });
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
      expect(exposed.exploitabilityAssessment).toBeUndefined();
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

describe("executeScan: customer-defined checks", () => {
  /** A scheduled-style scan with nuclei the only extended tool the profile keeps. */
  async function scanWithNucleiOnly(profile: "full" | "exposure") {
    customChecksMock.mockClear();
    nucleiMock.mockClear();
    const { client } = fakeSupabase();
    const toolOverrides = Object.fromEntries(EXTENDED_TOOL_NAMES.map((n) => [n, n === "nuclei"]));
    const scan = await executeScan(client, `scan-${profile}`, "owner-1", "https://shop.example", { profile, toolOverrides, confirmExploits: false });
    expect(scan.ok).toBe(true);
    expect(nucleiMock).toHaveBeenCalled();
  }

  it("runs the account's own checks alongside nuclei on an active profile", async () => {
    await scanWithNucleiOnly("full");
    expect(customChecksMock).toHaveBeenCalledWith(expect.anything(), "owner-1", "https://shop.example");
  });

  it("never runs them under the exposure profile, which promises no test payloads", async () => {
    await scanWithNucleiOnly("exposure");
    expect(customChecksMock).not.toHaveBeenCalled();
    expect(nucleiMock).toHaveBeenCalledWith("https://shop.example", expect.any(Array), { nonIntrusive: true });
  });
});

describe("executeScan: posture checks keyed on the owner's connections", () => {
  const onlyPosture = Object.fromEntries(EXTENDED_TOOL_NAMES.map((n) => [n, ["cloudPosture", "prowler", "m365", "workspace"].includes(n)]));
  const finding = (checkId: string) => ({ checkId, severity: "high", title: checkId, detail: "", remediation: "" });

  beforeEach(() => {
    for (const m of Object.values(posture)) m.mockReset();
  });

  async function scan() {
    const { client, resultInserts } = fakeSupabase();
    const result = await executeScan(client, "scan-posture", "owner-1", "https://shop.example", { profile: "full", toolOverrides: onlyPosture, confirmExploits: false });
    expect(result.ok).toBe(true);
    const stored = resultInserts[0].results as { extended: Record<string, { status: string; note?: string }>; findings: Array<{ checkId: string }> };
    return { extended: stored.extended, ids: stored.findings.map((f) => f.checkId) };
  }

  it("adds each check's findings and keeps its result", async () => {
    posture.cloud.mockResolvedValue({ status: "checked", findings: [finding("cloud-posture.s3-public")] });
    // A partly failed run's evidenced findings still count.
    posture.prowler.mockResolvedValue({ status: "error", note: "one account unreadable", findings: [finding("prowler.iam-admin")], accounts: [] });
    posture.m365.mockResolvedValue({ status: "error", findings: [finding("m365.mfa-off")] });
    posture.workspace.mockResolvedValue({ status: "checked", findings: [finding("workspace.2sv-off")] });
    const { extended, ids } = await scan();
    expect(ids).toEqual(expect.arrayContaining(["cloud-posture.s3-public", "prowler.iam-admin", "m365.mfa-off", "workspace.2sv-off"]));
    expect(extended.cloudPosture.status).toBe("checked");
    expect(extended.prowler.status).toBe("error");
  });

  it("adds nothing from a check that isn't connected or has no findings", async () => {
    posture.cloud.mockResolvedValue({ status: "not_configured" });
    posture.prowler.mockResolvedValue({ status: "not_configured", findings: [], accounts: [] });
    posture.m365.mockResolvedValue({ status: "not_configured", findings: [] });
    posture.workspace.mockResolvedValue({ status: "not_configured", findings: [] });
    const { extended, ids } = await scan();
    expect(ids.filter((id) => /^(cloud-posture|prowler|m365|workspace)\./.test(id))).toEqual([]);
    expect(extended.m365.status).toBe("not_configured");
  });

  it("records a check that throws as an error, and the scan still completes", async () => {
    for (const m of Object.values(posture)) m.mockRejectedValue(new Error("down"));
    const { extended } = await scan();
    expect(extended.cloudPosture).toEqual({ status: "error", note: "Cloud posture check failed" });
    expect(extended.prowler).toMatchObject({ status: "error", note: "Prowler IAM check failed" });
    expect(extended.m365).toEqual({ status: "error", note: "Microsoft 365 posture check failed" });
    expect(extended.workspace).toEqual({ status: "error", note: "Google Workspace posture check failed" });
  });
});

describe("executeScan: authenticated-scan credential and the tool kill switch", () => {
  const noTools = Object.fromEntries(EXTENDED_TOOL_NAMES.map((n) => [n, false]));

  it("skips the authenticated checks, and says so, when the stored credential can't be decrypted", async () => {
    resolveAuthMock.mockReturnValueOnce({ credential: null, decrypted: false });
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const { client } = fakeSupabase({ rows: { monitored_targets: { id: "t-1" }, target_auth_credentials: { auth_type: "cookie", cookie_value: "enc:v1:xxx" } } });
    const result = await executeScan(client, "scan-auth", "owner-1", "https://shop.example", { profile: "full", toolOverrides: noTools, confirmExploits: false });
    expect(result.ok).toBe(true);
    expect(resolveAuthMock).toHaveBeenCalledWith({ auth_type: "cookie", cookie_value: "enc:v1:xxx" });
    expect(errors).toHaveBeenCalledWith(expect.stringContaining("Could not decrypt the authenticated-scan credential"));
    errors.mockRestore();
  });

  it("treats an unreadable kill-switch table as nothing disabled", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const { client } = fakeSupabase({ failTable: "tool_kill_switches" });
    const result = await executeScan(client, "scan-ks", "owner-1", "https://shop.example", { profile: "full", toolOverrides: noTools, confirmExploits: false });
    expect(result.ok).toBe(true);
    expect(errors).toHaveBeenCalledWith(expect.stringContaining("tool kill-switch read failed"), expect.any(String));
    errors.mockRestore();
  });
});

describe("confirmExploitable", () => {
  const findings = [{ checkId: "headers.cors", severity: "medium" as const, title: "CORS", detail: "", remediation: "" }];

  it("is switched off everywhere by DISABLE_PROOF_OF_EXPLOIT=1", async () => {
    vi.stubEnv("DISABLE_PROOF_OF_EXPLOIT", "1");
    proofMock.mockClear();
    expect(await confirmExploitable("https://shop.example", findings)).toBe(findings);
    expect(proofMock).not.toHaveBeenCalled();
    vi.unstubAllEnvs();
  });

  it("leaves findings unconfirmed, never fails, when the re-check throws", async () => {
    proofMock.mockRejectedValueOnce(new Error("browser crashed"));
    expect(await confirmExploitable("https://shop.example", findings)).toBe(findings);
  });
});

describe("executeScan: the Slack and Teams change alert", () => {
  const noTools = Object.fromEntries(EXTENDED_TOOL_NAMES.map((n) => [n, false]));
  const sub = { plan: "pro", status: "active", slack_webhook_url: "https://hooks.slack.example/x", ms_teams_webhook_url: "https://teams.example/y" };

  async function scanWith(opts: { newFindings: number | null; sub?: unknown; admin?: boolean }) {
    reportMock.mockImplementationOnce((scanRow: { id: string; target_url: string }) => ({ scan_id: scanRow.id, target_url: scanRow.target_url, score: 88, new_finding_count: opts.newFindings, fixed_finding_count: null }));
    const { client } = fakeSupabase({ rows: { subscriptions: opts.sub ?? null, users: opts.admin ? { is_admin: true } : null } });
    const result = await executeScan(client, "scan-alert", "owner-1", "https://shop.example", { profile: "safe", toolOverrides: noTools, confirmExploits: false });
    expect(result.ok).toBe(true);
  }

  beforeEach(() => {
    slackMock.mockClear();
    teamsMock.mockClear();
  });

  it("goes to both webhooks when an active Pro scan found something new", async () => {
    await scanWith({ newFindings: 2, sub });
    const payload = expect.objectContaining({ scanId: "scan-alert", newFindingsCount: 2, fixedFindingsCount: 0 });
    expect(slackMock).toHaveBeenCalledWith(sub.slack_webhook_url, payload);
    expect(teamsMock).toHaveBeenCalledWith(sub.ms_teams_webhook_url, payload);
  });

  it("isn't sent when nothing is new, without a plan, on a lapsed or Basic plan, or with no webhook", async () => {
    await scanWith({ newFindings: 0, sub });
    await scanWith({ newFindings: null, sub });
    await scanWith({ newFindings: 2, sub: null });
    await scanWith({ newFindings: 2, sub: { ...sub, status: "past_due" } });
    await scanWith({ newFindings: 2, sub: { ...sub, plan: "basic" } });
    await scanWith({ newFindings: 2, sub: { ...sub, slack_webhook_url: null, ms_teams_webhook_url: null } });
    expect(slackMock).not.toHaveBeenCalled();
    expect(teamsMock).not.toHaveBeenCalled();
  });

  it("reaches an admin without a paid plan, and a failed webhook doesn't fail the scan", async () => {
    slackMock.mockRejectedValueOnce(new Error("410 gone"));
    teamsMock.mockRejectedValueOnce(new Error("timeout"));
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    await scanWith({ newFindings: 1, sub: { ...sub, status: "cancelled", plan: null }, admin: true });
    expect(errors).toHaveBeenCalledWith("[scanExecution] slack change alert failed:", "410 gone");
    expect(errors).toHaveBeenCalledWith("[scanExecution] teams change alert failed:", "timeout");
    errors.mockRestore();
  });
});

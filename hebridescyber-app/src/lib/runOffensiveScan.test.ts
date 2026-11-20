// @vitest-environment node
// runOffensiveScan end to end with a real tool process: a stop part-way kills the
// tool, refuses the next one, fails the run before anything is "stored", and is
// audited. Real timers and real child processes, so the kill path is the real one.
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";

const { audit } = vi.hoisted(() => ({ audit: vi.fn() }));
vi.mock("./audit", () => ({ logAuditEvent: audit }));

import { execTool } from "./execTool";
import type { OffensiveGateDecision } from "./offensiveGate";
import { runOffensiveScan } from "./offensiveWatchdog";
import { ToolHaltedError, assertNotHalted } from "./toolHalt";

const admin = {} as SupabaseClient;
const job = { id: "job-1", owner: "owner-1", target_url: "https://shop.example.com" };
const NODE = process.execPath;
const ALLOWED: OffensiveGateDecision = { allowed: true, engagementId: "eng-1" };
const STOPPED: OffensiveGateDecision = { allowed: false, reason: "out_of_engagement_scope", engagementId: "eng-1", scopeRefusal: "engagement_state_disallows" };

/** Stands in for executeScan: a long tool, then a second tool, then the store step guarded by assertNotHalted. */
async function fakeScan(stored: string[]) {
  await execTool(NODE, ["-e", "setTimeout(() => {}, 30000)"]).catch(() => undefined);
  await execTool(NODE, ["-e", "0"]).catch((err) => stored.push(err instanceof ToolHaltedError ? "second tool refused" : "second tool failed"));
  assertNotHalted();
  stored.push("results stored");
  return "done";
}

beforeEach(() => {
  audit.mockReset();
});

describe("runOffensiveScan", () => {
  it("stops a running tool when the gate starts refusing, and the run fails before storing anything", async () => {
    const stored: string[] = [];
    const check = vi.fn().mockResolvedValueOnce(ALLOWED).mockResolvedValue(STOPPED);
    const started = Date.now();
    await expect(runOffensiveScan(admin, job, "scan-1", "eng-1", () => fakeScan(stored), { intervalMs: 150, check })).rejects.toBeInstanceOf(ToolHaltedError);
    expect(Date.now() - started).toBeLessThan(10_000);
    expect(stored).toEqual(["second tool refused"]);
    expect(audit).toHaveBeenCalledTimes(1);
    expect(audit.mock.calls[0][1]).toMatchObject({
      action: "offensive_scan.halted",
      resourceType: "scan_job",
      resourceId: "job-1",
      metadata: { scan_id: "scan-1", engagement_id: "eng-1", reason: "out_of_engagement_scope", scope_refusal: "engagement_state_disallows", tools_running: 1 },
    });
  });

  it("leaves a run alone while the gate keeps passing, and stops checking afterwards", async () => {
    const check = vi.fn().mockResolvedValue(ALLOWED);
    const result = await runOffensiveScan(admin, job, "scan-1", null, async () => {
      await new Promise((r) => setTimeout(r, 400));
      await execTool(NODE, ["-e", "0"]);
      assertNotHalted();
      return "done";
    }, { intervalMs: 100, check });
    expect(result).toBe("done");
    const calls = check.mock.calls.length;
    expect(calls).toBeGreaterThan(0);
    await new Promise((r) => setTimeout(r, 300));
    expect(check.mock.calls.length).toBe(calls);
    expect(audit).not.toHaveBeenCalled();
  });
});

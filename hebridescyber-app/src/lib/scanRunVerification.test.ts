import { describe, it, expect } from "vitest";
import { verifyScanRun, formatScanRunSummary, type ScanRunJob, type ScanRunResult } from "./scanRunVerification";

const job = (id: string, status: string, scanId: string | null = `scan-${id}`, lastError: string | null = null): ScanRunJob => ({
  id,
  status,
  scan_id: scanId,
  last_error: lastError,
});

describe("verifyScanRun", () => {
  it("passes when a scan's extended tools completed, and counts every status", () => {
    const results: ScanRunResult[] = [
      { scan_id: "scan-1", extended: { nuclei: { status: "completed", findings: [] }, zap: { status: "not_configured" }, katana: { status: "partial" } } },
      { scan_id: "scan-2", extended: { nuclei: { status: "error", note: "timeout" }, zap: { status: "not_configured" } } },
    ];
    const v = verifyScanRun([job("1", "completed"), job("2", "completed")], results);
    expect(v.verdict).toBe("ok");
    expect(v.scansWithExtended).toBe(2);
    expect(v.toolStatus.nuclei).toEqual({ completed: 1, error: 1 });
    expect(v.toolStatus.zap).toEqual({ not_configured: 2 });
    // partial proves the tool ran
    expect(v.toolsCompleted).toEqual(["katana", "nuclei"]);
  });

  it("fails when the extended tier ran but no tool completed anywhere", () => {
    const results: ScanRunResult[] = [{ scan_id: "scan-1", extended: { nuclei: { status: "not_configured" }, zap: { status: "error" } } }];
    const v = verifyScanRun([job("1", "completed")], results);
    expect(v.verdict).toBe("fail");
    expect(v.toolsCompleted).toEqual([]);
    expect(v.problems.join(" ")).toMatch(/no tool completed/);
  });

  it("never counts a status it can't read as completed", () => {
    const results: ScanRunResult[] = [{ scan_id: "scan-1", extended: { nuclei: "completed", zap: null, sqlmap: { status: 1 } } }];
    const v = verifyScanRun([job("1", "completed")], results);
    expect(v.verdict).toBe("fail");
    expect(v.toolStatus.nuclei).toEqual({ unreadable: 1 });
    expect(v.toolStatus.zap).toEqual({ unreadable: 1 });
  });

  it("reports nothing_ran when no job was claimed (no target was due)", () => {
    const v = verifyScanRun([], []);
    expect(v.verdict).toBe("nothing_ran");
    expect(v.problems).toEqual([]);
  });

  it("fails when every claimed job failed", () => {
    const v = verifyScanRun([job("1", "failed", null, "SSRF check rejected the target")], []);
    expect(v.verdict).toBe("fail");
    expect(v.problems).toEqual(["job 1 failed: SSRF check rejected the target", "no claimed job completed"]);
  });

  it("fails when a completed scan has no result row", () => {
    const v = verifyScanRun([job("1", "completed")], []);
    expect(v.verdict).toBe("fail");
    expect(v.problems).toEqual(["scan scan-1 is marked completed but has no result row"]);
  });

  it("passes a safe-profile run (base checks only) and still lists failed and unfinished jobs", () => {
    const v = verifyScanRun(
      [job("1", "completed"), job("2", "failed", null, "boom"), job("3", "running")],
      [{ scan_id: "scan-1", extended: null }],
    );
    expect(v.verdict).toBe("ok");
    expect(v.scansWithExtended).toBe(0);
    expect(v.jobs).toEqual({ total: 3, completed: 1, failed: 1, unfinished: 1 });
    expect(v.problems).toEqual(["job 2 failed: boom", "1 job(s) were still pending or running when the shards finished"]);
  });

  it("skips a completed job with no scan (already done by an earlier run)", () => {
    const v = verifyScanRun([job("1", "completed", null), job("2", "completed")], [{ scan_id: "scan-2", extended: { nuclei: { status: "completed" } } }]);
    expect(v.verdict).toBe("ok");
    expect(v.problems).toEqual([]);
  });
});

describe("formatScanRunSummary", () => {
  it("renders the verdict, the per-tool table and the problems", () => {
    const v = verifyScanRun(
      [job("1", "completed"), job("2", "failed", null, "boom")],
      [{ scan_id: "scan-1", extended: { zap: { status: "not_configured" }, nuclei: { status: "completed" } } }],
    );
    const md = formatScanRunSummary(v);
    expect(md).toContain("Scheduled scan run verified");
    expect(md).toContain("Jobs: 2 claimed, 1 completed, 1 failed, 0 unfinished. Scans with extended tools: 1.");
    expect(md).toContain("| nuclei | completed ×1 |");
    expect(md).toContain("| zap | not_configured ×1 |");
    expect(md).toContain("- job 2 failed: boom");
    expect(md.indexOf("| nuclei")).toBeLessThan(md.indexOf("| zap"));
  });

  it("says plainly when nothing was due", () => {
    expect(formatScanRunSummary(verifyScanRun([], []))).toContain("No scan jobs were due");
  });
});

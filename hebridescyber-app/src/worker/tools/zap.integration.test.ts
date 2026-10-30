// Runs the real OWASP ZAP daemon against the local test app
// (tests/fixtures/test-app). Skipped unless RUN_TOOL_INTEGRATION=1: it needs a
// ZAP daemon reachable at ZAP_API_URL with ZAP_API_KEY, plus the app running —
// the tool-integration CI job starts the pinned ZAP image with --network host
// (so the container's loopback reaches the 127.0.0.1-bound test app) and a
// random per-run API key.
//
// ZAP runs in the default `full` profile but had no real-binary test. This
// exercises the whole spider -> active-scan -> collect-alerts -> map-to-Finding
// path against real daemon JSON, which the unit tests can only mock. It also
// covers passive-only mode (the `exposure` profile): spider -> passive-queue
// drain -> collect-alerts, and asks the daemon itself that no active scan ran.
import { describe, it, expect } from "vitest";
import { runZap } from "./zap";

const base = process.env.TEST_APP_URL ?? "http://127.0.0.1:8099";

describe.skipIf(process.env.RUN_TOOL_INTEGRATION !== "1")("ZAP against the local test app", () => {
  // Runs first, on a daemon that has never active-scanned, so its alerts can
  // only come from passive rules and the daemon's scan list must stay empty.
  it("completes a passive-only scan with no active scan and returns well-formed alerts", async () => {
    // Missing security headers are passive-rule alerts, so the app yields at
    // least one alert without the active scanner ever running.
    const result = await runZap(`${base}/`, { passiveOnly: true });
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    expect(result.alerts.length, "ZAP's passive rules should report at least one alert").toBeGreaterThan(0);
    expect(result.findings.length).toBe(result.alerts.length);
    for (const f of result.findings) {
      expect(f.checkId).toMatch(/^zap\.alert:/);
      expect(["info", "low", "medium", "high"]).toContain(f.severity);
    }
    const res = await fetch(
      `${process.env.ZAP_API_URL}/JSON/ascan/view/scans/?apikey=${encodeURIComponent(process.env.ZAP_API_KEY ?? "")}`
    );
    const { scans } = (await res.json()) as { scans: unknown[] };
    expect(scans, "passive-only mode must not start an active scan").toEqual([]);
  }, 300_000);

  it("completes a spider + active scan and returns well-formed alerts", async () => {
    // Target the home page so ZAP's spider discovers the <form> and the links
    // (/item, /search) and scans them. ZAP's passive scanner flags missing
    // security headers on any HTTP response, so a completed scan of this app
    // reliably yields at least one alert — we assert the shape, not a specific
    // vulnerability, to avoid coupling the test to ZAP's scan-policy tuning.
    const result = await runZap(`${base}/`);
    if (result.status !== "completed") throw new Error(`expected completed, got ${JSON.stringify(result)}`);
    expect(Array.isArray(result.alerts)).toBe(true);
    expect(result.alerts.length, "ZAP should report at least one alert").toBeGreaterThan(0);
    // Every alert must map to a Finding with a stable, prefixed checkId.
    expect(result.findings.length).toBe(result.alerts.length);
    for (const f of result.findings) {
      expect(f.checkId).toMatch(/^zap\.alert:/);
      expect(["info", "low", "medium", "high"]).toContain(f.severity);
    }
  }, 420_000);
});

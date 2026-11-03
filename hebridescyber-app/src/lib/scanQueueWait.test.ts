import { describe, it, expect } from "vitest";
import { QUEUE_WAIT_ALERT_SECONDS, decideQueueWait, queueWaitAlertEnabled, queueWaitSeconds } from "./scanQueueWait";

const NOW = new Date("2026-11-01T12:00:00Z");

describe("queueWaitSeconds", () => {
  it("is the oldest pending job's age in whole seconds", () => {
    expect(queueWaitSeconds("2026-11-01T11:59:30.900Z", NOW)).toBe(29);
    expect(queueWaitSeconds("2026-11-01T09:00:00Z", NOW)).toBe(3 * 60 * 60);
  });

  it("reads Postgres timestamptz text as PostgREST returns it", () => {
    expect(queueWaitSeconds("2026-11-01T10:00:00.123456+00:00", NOW)).toBe(2 * 60 * 60 - 1);
  });

  it("is 0 when nothing is pending", () => {
    expect(queueWaitSeconds(null, NOW)).toBe(0);
    expect(queueWaitSeconds(undefined, NOW)).toBe(0);
    expect(queueWaitSeconds("", NOW)).toBe(0);
  });

  it("counts a created_at in the future (clock skew) as no wait", () => {
    expect(queueWaitSeconds("2026-11-01T12:05:00Z", NOW)).toBe(0);
  });

  it("is null, not 0, for a timestamp that doesn't parse, so a broken row never reads as an empty queue", () => {
    expect(queueWaitSeconds("not a date", NOW)).toBeNull();
  });
});

describe("queueWaitAlertEnabled", () => {
  it("is off by default, while the daily Actions fallback is the only worker", () => {
    expect(queueWaitAlertEnabled({})).toBe(false);
  });

  it.each(["1", "true", "TRUE", " 1 "])("is on for %j", (value) => {
    expect(queueWaitAlertEnabled({ SCAN_QUEUE_WAIT_ALERT: value })).toBe(true);
  });

  it.each(["0", "false", "", "yes"])("stays off for %j", (value) => {
    expect(queueWaitAlertEnabled({ SCAN_QUEUE_WAIT_ALERT: value })).toBe(false);
  });
});

describe("decideQueueWait", () => {
  it("uses a two-hour threshold", () => {
    expect(QUEUE_WAIT_ALERT_SECONDS).toBe(7200);
  });

  it("alerts once the oldest job has waited past two hours", () => {
    expect(decideQueueWait(7201, { alertEnabled: true })).toEqual({ oldestWaitSeconds: 7201, waitExceeded: true });
  });

  it("does not alert at exactly two hours, or under", () => {
    expect(decideQueueWait(7200, { alertEnabled: true }).waitExceeded).toBe(false);
    expect(decideQueueWait(0, { alertEnabled: true }).waitExceeded).toBe(false);
  });

  it("reports the wait but never alerts while the alert is switched off", () => {
    expect(decideQueueWait(86_400, { alertEnabled: false })).toEqual({ oldestWaitSeconds: 86_400, waitExceeded: false });
  });

  it("honours a custom threshold", () => {
    expect(decideQueueWait(601, { alertEnabled: true, thresholdSeconds: 600 }).waitExceeded).toBe(true);
    expect(decideQueueWait(599, { alertEnabled: true, thresholdSeconds: 600 }).waitExceeded).toBe(false);
  });
});

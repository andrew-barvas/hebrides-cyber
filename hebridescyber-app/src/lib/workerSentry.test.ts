import { beforeEach, describe, expect, it, vi } from "vitest";

const sentry = vi.hoisted(() => {
  const scope = { setTag: vi.fn(), setFingerprint: vi.fn() };
  return {
    scope,
    init: vi.fn(),
    setTag: vi.fn(),
    captureException: vi.fn(),
    flush: vi.fn(async () => true),
    withScope: vi.fn((cb: (s: typeof scope) => void) => cb(scope)),
  };
});
vi.mock("@sentry/node", () => sentry);

import {
  captureWorkerError,
  captureWorkerFatal,
  correlationId,
  flushWorkerSentry,
  initWorkerSentry,
  logPrefix,
  resetWorkerSentryForTests,
} from "./workerSentry";

const job = { workerId: "gha-1-0", jobId: "job-1", scanId: "scan-1", targetUrl: "https://shop.example.co.uk/path?token=secret" };

beforeEach(() => {
  vi.clearAllMocks();
  resetWorkerSentryForTests();
});

describe("correlationId / logPrefix", () => {
  it("uses the scan id when there is one, else the job id", () => {
    expect(correlationId({ id: "job-1", scan_id: "scan-1" })).toBe("scan-1");
    expect(correlationId({ id: "job-1", scan_id: null })).toBe("job-1");
    expect(logPrefix({ id: "job-1", scan_id: "scan-1" })).toBe("[scan scan-1]");
    expect(logPrefix({ id: "job-1", scan_id: null })).toBe("[job job-1]");
  });
});

describe("initWorkerSentry", () => {
  it("is a no-op without a DSN", () => {
    expect(initWorkerSentry("w", {})).toBe(false);
    expect(sentry.init).not.toHaveBeenCalled();
    captureWorkerError(new Error("x"), job, "run");
    expect(sentry.captureException).not.toHaveBeenCalled();
  });

  it("initialises once, errors only, with the scrubber", () => {
    expect(initWorkerSentry("w", { SENTRY_DSN: "https://k@o.ingest.sentry.io/1" })).toBe(true);
    expect(initWorkerSentry("w", { SENTRY_DSN: "https://k@o.ingest.sentry.io/1" })).toBe(true);
    expect(sentry.init).toHaveBeenCalledTimes(1);
    expect(sentry.init).toHaveBeenCalledWith(expect.objectContaining({ environment: "worker", tracesSampleRate: 0, beforeSend: expect.any(Function) }));
  });
});

describe("captureWorkerError", () => {
  beforeEach(() => {
    initWorkerSentry("w", { SENTRY_DSN: "https://k@o.ingest.sentry.io/1" });
  });

  it("tags the correlation ids and the host only, never the full URL", () => {
    captureWorkerError(new Error("boom"), job, "job");
    const tags = Object.fromEntries(sentry.scope.setTag.mock.calls);
    expect(tags).toMatchObject({ stage: "job", worker_id: "gha-1-0", job_id: "job-1", scan_id: "scan-1", correlation_id: "scan-1", target_host: "shop.example.co.uk" });
    expect(JSON.stringify(sentry.scope.setTag.mock.calls)).not.toContain("secret");
    expect(sentry.captureException).toHaveBeenCalledWith(expect.objectContaining({ message: "boom" }));
  });

  it("falls back to the job id as correlation id and wraps non-errors", () => {
    captureWorkerError("plain string", { ...job, scanId: null }, "run");
    expect(Object.fromEntries(sentry.scope.setTag.mock.calls).correlation_id).toBe("job-1");
    expect(sentry.captureException).toHaveBeenCalledWith(expect.objectContaining({ message: "plain string" }));
  });

  it("groups by stage, not by scan", () => {
    captureWorkerError(new TypeError("a"), job, "run");
    expect(sentry.scope.setFingerprint).toHaveBeenCalledWith(["worker", "run", "TypeError"]);
  });

  it("never throws, even if Sentry does", () => {
    sentry.withScope.mockImplementationOnce(() => {
      throw new Error("sentry down");
    });
    expect(() => captureWorkerError(new Error("x"), job, "run")).not.toThrow();
  });
});

describe("captureWorkerFatal / flushWorkerSentry", () => {
  it("reports a job-less failure and flushes", async () => {
    initWorkerSentry("w", { SENTRY_DSN: "https://k@o.ingest.sentry.io/1" });
    captureWorkerFatal(new Error("claim down"), "w", "claim");
    expect(sentry.captureException).toHaveBeenCalledTimes(1);
    await flushWorkerSentry(500);
    expect(sentry.flush).toHaveBeenCalledWith(500);
  });

  it("does nothing, and does not flush, when uninitialised", async () => {
    captureWorkerFatal(new Error("x"), "w", "main");
    await flushWorkerSentry();
    expect(sentry.captureException).not.toHaveBeenCalled();
    expect(sentry.flush).not.toHaveBeenCalled();
  });

  it("swallows a flush failure", async () => {
    initWorkerSentry("w", { SENTRY_DSN: "https://k@o.ingest.sentry.io/1" });
    sentry.flush.mockRejectedValueOnce(new Error("network"));
    await expect(flushWorkerSentry()).resolves.toBeUndefined();
  });
});

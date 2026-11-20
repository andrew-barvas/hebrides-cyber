import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { startOffensiveWatchdog } from "./offensiveWatchdog";
import { HaltController } from "./toolHalt";

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

const ALLOWED = { allowed: true as const, engagementId: "eng-1" };
const REFUSED = { allowed: false as const, reason: "out_of_engagement_scope" as const, engagementId: "eng-1", scopeRefusal: "engagement_state_disallows" as const };

describe("startOffensiveWatchdog", () => {
  it("keeps asking while the gate passes, and halts with the reason once it doesn't", async () => {
    const controller = new HaltController();
    const check = vi.fn().mockResolvedValueOnce(ALLOWED).mockResolvedValueOnce(ALLOWED).mockResolvedValue(REFUSED);
    const onHalt = vi.fn();
    const dog = startOffensiveWatchdog({ controller, check, onHalt, intervalMs: 1000 });

    await vi.advanceTimersByTimeAsync(2000);
    expect(check).toHaveBeenCalledTimes(2);
    expect(controller.halted).toBe(false);

    await vi.advanceTimersByTimeAsync(1000);
    expect(controller.halted).toBe(true);
    expect(controller.reason).toBe("target is outside the engagement's signed scope or window (engagement_state_disallows)");
    expect(onHalt).toHaveBeenCalledWith(REFUSED);

    await vi.advanceTimersByTimeAsync(5000);
    expect(check).toHaveBeenCalledTimes(3);
    expect(onHalt).toHaveBeenCalledTimes(1);
    dog.stop();
  });

  it("halts when the check itself throws", async () => {
    const controller = new HaltController();
    const onHalt = vi.fn();
    startOffensiveWatchdog({ controller, check: vi.fn().mockRejectedValue(new Error("db down")), onHalt, intervalMs: 1000 });
    await vi.advanceTimersByTimeAsync(1000);
    expect(controller.halted).toBe(true);
    expect(controller.reason).toBe("the authorisation could not be re-checked");
    expect(onHalt).toHaveBeenCalledWith({ allowed: false, reason: "check_failed" });
  });

  it("does nothing after stop, even if a check was in flight", async () => {
    const controller = new HaltController();
    let resolve: (v: typeof REFUSED) => void = () => {};
    const check = vi.fn(() => new Promise<typeof REFUSED>((r) => (resolve = r)));
    const dog = startOffensiveWatchdog({ controller, check, onHalt: vi.fn(), intervalMs: 1000 });
    await vi.advanceTimersByTimeAsync(1000);
    dog.stop();
    resolve(REFUSED);
    await vi.advanceTimersByTimeAsync(5000);
    expect(controller.halted).toBe(false);
    expect(check).toHaveBeenCalledTimes(1);
  });

  it("never overlaps checks, and a failing onHalt doesn't undo the halt", async () => {
    const controller = new HaltController();
    let resolve: (v: typeof REFUSED) => void = () => {};
    const check = vi.fn(() => new Promise<typeof REFUSED>((r) => (resolve = r)));
    startOffensiveWatchdog({ controller, check, onHalt: () => Promise.reject(new Error("audit down")), intervalMs: 1000 });
    await vi.advanceTimersByTimeAsync(3500);
    expect(check).toHaveBeenCalledTimes(1);
    resolve(REFUSED);
    await vi.advanceTimersByTimeAsync(0);
    expect(controller.halted).toBe(true);
  });
});

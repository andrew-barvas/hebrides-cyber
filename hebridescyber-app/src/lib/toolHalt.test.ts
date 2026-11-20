// @vitest-environment node
import { describe, it, expect, vi } from "vitest";
import { execTool } from "./execTool";
import { HaltController, KILL_GRACE_MS, ToolHaltedError, assertNotHalted, currentHalt, runWithHalt } from "./toolHalt";

// Real child processes (node itself), so the kill path is exercised for real.
const NODE = process.execPath;
const sleeper = (ms: number) => [NODE, ["-e", `setTimeout(() => {}, ${ms})`]] as const;

describe("runWithHalt", () => {
  it("has no controller outside a halted scope, and execTool runs as before", async () => {
    expect(currentHalt()).toBeUndefined();
    expect(() => assertNotHalted()).not.toThrow();
    const { stdout } = await execTool(NODE, ["-e", "process.stdout.write('ok')"]);
    expect(stdout).toBe("ok");
  });

  it("gives code inside it, across awaits, the same controller", async () => {
    const controller = new HaltController();
    await runWithHalt(controller, async () => {
      await new Promise((r) => setTimeout(r, 5));
      expect(currentHalt()).toBe(controller);
    });
    expect(currentHalt()).toBeUndefined();
  });
});

describe("HaltController with execTool", () => {
  it("kills a running tool on halt, so its call rejects promptly", async () => {
    const controller = new HaltController();
    const started = Date.now();
    await runWithHalt(controller, async () => {
      const [file, args] = sleeper(30_000);
      const running = execTool(file, args);
      await new Promise((r) => setTimeout(r, 200));
      expect(controller.running).toBe(1);
      controller.halt("engagement aborted");
      await expect(running).rejects.toBeTruthy();
    });
    expect(Date.now() - started).toBeLessThan(10_000);
    expect(controller.running).toBe(0);
    expect(controller.reason).toBe("engagement aborted");
  });

  it("starts nothing once halted: a later call rejects with ToolHaltedError without spawning", async () => {
    const controller = new HaltController();
    controller.halt("window closed");
    await runWithHalt(controller, async () => {
      const [file, args] = sleeper(30_000);
      await expect(execTool(file, args)).rejects.toBeInstanceOf(ToolHaltedError);
      expect(controller.running).toBe(0);
      expect(() => assertNotHalted()).toThrow(/Testing was stopped part-way: window closed/);
    });
  });

  it("only affects tools in its own scope", async () => {
    const a = new HaltController();
    const b = new HaltController();
    await Promise.all([
      runWithHalt(a, async () => {
        a.halt("stop a");
        await expect(execTool(NODE, ["-e", "0"])).rejects.toBeInstanceOf(ToolHaltedError);
      }),
      runWithHalt(b, async () => {
        await new Promise((r) => setTimeout(r, 20));
        await expect(execTool(NODE, ["-e", "0"])).resolves.toBeTruthy();
      }),
    ]);
  });

  it("forgets a tool that finished on its own, and halting twice keeps the first reason", async () => {
    const controller = new HaltController();
    await runWithHalt(controller, () => execTool(NODE, ["-e", "0"]));
    expect(controller.running).toBe(0);
    controller.halt("first");
    controller.halt("second");
    expect(controller.reason).toBe("first");
  });
});

describe("HaltController kill path (fake processes)", () => {
  type FakeChild = import("node:events").EventEmitter & { kill: ReturnType<typeof vi.fn>; exitCode: number | null; signalCode: string | null };
  const fake = async (): Promise<FakeChild> => {
    const { EventEmitter } = await import("node:events");
    return Object.assign(new EventEmitter(), { kill: vi.fn(), exitCode: null, signalCode: null }) as FakeChild;
  };

  it("forces a tool that ignores SIGTERM after the grace period, and leaves one that exited alone", async () => {
    vi.useFakeTimers();
    try {
      const stubborn = await fake();
      const polite = await fake();
      const controller = new HaltController();
      controller.register(stubborn as never);
      controller.register(polite as never);
      controller.halt("stop");
      expect(stubborn.kill).toHaveBeenCalledWith("SIGTERM");
      polite.exitCode = 0;
      vi.advanceTimersByTime(KILL_GRACE_MS);
      expect(stubborn.kill).toHaveBeenLastCalledWith("SIGKILL");
      expect(polite.kill).not.toHaveBeenCalledWith("SIGKILL");
    } finally {
      vi.useRealTimers();
    }
  });

  it("kills a process registered after the halt straight away, and survives a kill that throws", async () => {
    vi.useFakeTimers();
    try {
      const late = await fake();
      late.kill.mockImplementation(() => {
        throw new Error("ESRCH");
      });
      const controller = new HaltController();
      controller.halt("stop");
      expect(() => controller.register(late as never)).not.toThrow();
      expect(late.kill).toHaveBeenCalledWith("SIGTERM");
      expect(controller.running).toBe(0);
      expect(() => vi.advanceTimersByTime(KILL_GRACE_MS)).not.toThrow();
      expect(late.kill).toHaveBeenLastCalledWith("SIGKILL");
    } finally {
      vi.useRealTimers();
    }
  });

  it("forgets a process that fails to start", async () => {
    const broken = await fake();
    const controller = new HaltController();
    controller.register(broken as never);
    expect(controller.running).toBe(1);
    broken.emit("error", new Error("ENOENT"));
    expect(controller.running).toBe(0);
  });
});

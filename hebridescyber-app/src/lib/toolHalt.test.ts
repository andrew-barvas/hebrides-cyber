// @vitest-environment node
import { describe, it, expect } from "vitest";
import { execTool } from "./execTool";
import { HaltController, ToolHaltedError, assertNotHalted, currentHalt, runWithHalt } from "./toolHalt";

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

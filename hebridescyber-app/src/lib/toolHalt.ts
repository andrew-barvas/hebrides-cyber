// Stopping a scan's external tools part-way (Exploit, P-07: "an immediate stop").
//
// The worker runs an offensive scan inside runWithHalt(controller, ...). Every
// tool process started through execTool inside that call registers with the
// controller, found through AsyncLocalStorage so no wrapper needs a new
// parameter. controller.halt() then:
//   - kills every registered process (SIGTERM, then SIGKILL after a grace period),
//   - makes every later execTool call in that scan reject at once, starting nothing,
//   - makes executeScan fail the scan before it stores results (assertNotHalted),
//     so partial output from a stopped run never marks last scan's findings fixed.
// Outside runWithHalt nothing changes: there is no controller, and execTool
// behaves exactly as before.
//
// What it can't stop: requests a check makes itself with fetch rather than an
// external tool. Those are the passive base checks, not the offensive suite.
import { AsyncLocalStorage } from "node:async_hooks";
import type { ChildProcess } from "node:child_process";

export class ToolHaltedError extends Error {
  readonly code = "EHALTED";
  constructor(reason: string) {
    super(`Testing was stopped part-way: ${reason}`);
    this.name = "ToolHaltedError";
  }
}

/** Grace period between asking a tool to stop and forcing it. */
export const KILL_GRACE_MS = 5_000;

export class HaltController {
  private haltedReason: string | null = null;
  private readonly children = new Set<ChildProcess>();

  get halted(): boolean {
    return this.haltedReason !== null;
  }

  get reason(): string | null {
    return this.haltedReason;
  }

  /** Number of tool processes currently running under this controller. */
  get running(): number {
    return this.children.size;
  }

  /** Tracks a tool process until it exits. Called by execTool. A process started after a halt is killed at once. */
  register(child: ChildProcess): void {
    if (this.halted) {
      kill(child);
      return;
    }
    this.children.add(child);
    const forget = () => this.children.delete(child);
    child.once("exit", forget);
    child.once("error", forget);
  }

  /** Stops every running tool and refuses new ones. Calling it again does nothing. */
  halt(reason: string): void {
    if (this.halted) return;
    this.haltedReason = reason;
    for (const child of this.children) kill(child);
  }
}

function kill(child: ChildProcess): void {
  try {
    child.kill("SIGTERM");
  } catch {
    // already gone
  }
  const force = setTimeout(() => {
    if (child.exitCode === null && child.signalCode === null) {
      try {
        child.kill("SIGKILL");
      } catch {
        // already gone
      }
    }
  }, KILL_GRACE_MS);
  force.unref?.();
}

const storage = new AsyncLocalStorage<HaltController>();

export function runWithHalt<T>(controller: HaltController, fn: () => Promise<T>): Promise<T> {
  return storage.run(controller, fn);
}

/** The controller for the scan this code is running in, if any. */
export function currentHalt(): HaltController | undefined {
  return storage.getStore();
}

/** Throws ToolHaltedError if the current scan has been halted. */
export function assertNotHalted(): void {
  const controller = currentHalt();
  if (controller?.halted) throw new ToolHaltedError(controller.reason ?? "stopped");
}

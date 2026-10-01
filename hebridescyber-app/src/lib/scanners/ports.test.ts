import { describe, it, expect, vi, beforeEach } from "vitest";
import { EventEmitter } from "node:events";

const { createConnectionMock } = vi.hoisted(() => ({ createConnectionMock: vi.fn() }));

// Static factory — see dns.test.ts for why importOriginal doesn't intercept.
vi.mock("node:net", () => {
  const exports = { createConnection: createConnectionMock };
  return { ...exports, default: exports };
});

import { checkOpenPorts } from "./ports";

/** Fake socket: "open" ports connect, "timeout" ports time out, the rest error. */
function network(open: number[], timeout: number[] = []) {
  createConnectionMock.mockImplementation((opts: { port?: number } | undefined, onConnect?: () => void) => {
    const socket = Object.assign(new EventEmitter(), { destroy: vi.fn(), setTimeout: vi.fn() });
    const port = opts?.port;
    // Calls that aren't ports.ts probes (the test environment's own) get an
    // idle socket — emitting "error" on one with no listener would throw.
    if (port === undefined) return socket;
    queueMicrotask(() => {
      if (open.includes(port)) onConnect?.();
      else if (timeout.includes(port)) socket.emit("timeout");
      else socket.emit("error", new Error("ECONNREFUSED"));
    });
    return socket;
  });
}

/** Only the probes ports.ts made (the mock is module-wide). */
const probes = () =>
  createConnectionMock.mock.calls
    .map((args, i) => ({ opts: args[0] as { host?: string; port?: number } | undefined, socket: createConnectionMock.mock.results[i].value }))
    .filter((c) => typeof c.opts?.port === "number" && typeof c.opts?.host === "string");

beforeEach(() => {
  createConnectionMock.mockReset();
});

describe("checkOpenPorts", () => {
  it("reports open ports and separates the risky ones", async () => {
    network([22, 443, 6379, 3306]);
    const result = await checkOpenPorts("https://example.com");
    if (result.status !== "checked") throw new Error("expected checked");
    expect(result.openPorts.map((p) => p.port).sort((a, b) => a - b)).toEqual([22, 443, 3306, 6379]);
    expect(result.riskyPorts.map((p) => `${p.port}:${p.risk}`).sort()).toEqual(["3306:high", "6379:critical"]);
  });

  it("treats timeouts and refusals as closed", async () => {
    network([], [3389]);
    expect(await checkOpenPorts("https://example.com")).toEqual({ status: "checked", openPorts: [], riskyPorts: [] });
  });

  it("probes the target's hostname, 30 ports", async () => {
    network([]);
    await checkOpenPorts("https://shop.example.com:8443/basket");
    expect(probes()).toHaveLength(30);
    expect(probes().every((p) => p.opts!.host === "shop.example.com")).toBe(true);
  });

  it("closes a socket once it connects", async () => {
    network([443]);
    await checkOpenPorts("https://example.com");
    const https = probes().find((p) => p.opts!.port === 443)!;
    expect(https.socket.destroy).toHaveBeenCalled();
  });
});

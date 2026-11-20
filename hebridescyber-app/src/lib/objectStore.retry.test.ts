import { describe, it, expect, vi } from "vitest";
import { memoryObjectStore, withRetries, type ObjectStore } from "./objectStore";

const noSleep = { sleep: async () => {} };

describe("withRetries", () => {
  it("retries a failing get until it succeeds, with exponential back-off", async () => {
    const inner = memoryObjectStore({ k: Buffer.from("v") });
    const get = vi.fn().mockRejectedValueOnce(new Error("fetch failed")).mockRejectedValueOnce(new Error("ECONNRESET")).mockImplementation((key: string) => inner.get(key));
    const sleep = vi.fn(async (_ms: number) => {});
    const store = withRetries({ get, put: inner.put } as ObjectStore, { sleep, baseDelayMs: 100 });
    expect((await store.get("k"))?.toString()).toBe("v");
    expect(get).toHaveBeenCalledTimes(3);
    expect(sleep.mock.calls.map((c) => c[0])).toEqual([100, 200]);
  });

  it("never retries a missing object", async () => {
    const get = vi.fn(async () => null);
    expect(await withRetries({ get, put: vi.fn() } as ObjectStore, noSleep).get("k")).toBeNull();
    expect(get).toHaveBeenCalledTimes(1);
  });

  it("gives up after the last attempt with the last error", async () => {
    const put = vi.fn(async () => {
      throw new Error("fetch failed");
    });
    await expect(withRetries({ get: vi.fn(), put } as ObjectStore, { ...noSleep, attempts: 3 }).put("k", Buffer.from("x"))).rejects.toThrow("fetch failed");
    expect(put).toHaveBeenCalledTimes(3);
  });

  it("retries puts too", async () => {
    const inner = memoryObjectStore();
    const put = vi.fn().mockRejectedValueOnce(new Error("503")).mockImplementation((k: string, d: Buffer) => inner.put(k, d));
    await withRetries({ get: inner.get, put } as ObjectStore, noSleep).put("k", Buffer.from("x"));
    expect(inner.keys()).toEqual(["k"]);
  });
});

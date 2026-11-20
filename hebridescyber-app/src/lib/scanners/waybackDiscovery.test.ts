import { afterEach, describe, expect, it, vi } from "vitest";
import { checkWaybackDiscovery } from "./waybackDiscovery";
import { isCovered, scanCoverage } from "../findingLifecycle";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("checkWaybackDiscovery when the archive can't be read (audit M3)", () => {
  it.each([
    ["a network failure", () => Promise.reject(new Error("ETIMEDOUT"))],
    ["an HTTP error", () => Promise.resolve(new Response("busy", { status: 503 }))],
    ["an unreadable body", () => Promise.resolve(new Response("<html>", { status: 200 }))],
  ])("is partial on %s, never a clean checked", async (_label, reply) => {
    vi.stubGlobal("fetch", vi.fn(reply));
    const r = await checkWaybackDiscovery("https://www.example.com");
    expect(r.status).toBe("partial");
  });

  it("is checked with nothing found when the archive is genuinely empty", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify([["original", "statuscode", "mimetype"]]), { status: 200 }))));
    expect(await checkWaybackDiscovery("https://www.example.com")).toMatchObject({ status: "checked", discovered: [] });
  });

  it("so last scan's wayback findings stay open instead of being marked fixed", () => {
    const coverage = scanCoverage(null, { waybackDiscovery: { status: "partial", note: "x", discovered: [] } });
    expect(isCovered("base", coverage, "wayback-discovery.live-path:/old-admin")).toBe(false);
    const ok = scanCoverage(null, { waybackDiscovery: { status: "checked", discovered: [] } });
    expect(isCovered("base", ok, "wayback-discovery.live-path:/old-admin")).toBe(true);
  });
});

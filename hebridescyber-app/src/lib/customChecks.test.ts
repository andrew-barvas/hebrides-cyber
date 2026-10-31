import { describe, it, expect, vi, beforeEach } from "vitest";

const { gate } = vi.hoisted(() => ({ gate: vi.fn() }));
vi.mock("./planAccess", () => ({ planGate: gate }));

import { runCustomChecksForOwner } from "./customChecks";

function db(result: { data?: unknown; error?: { message: string } | null }) {
  const calls: [string, unknown][] = [];
  const q: Record<string, unknown> = {
    select: () => q,
    eq: (c: string, v: unknown) => (calls.push([c, v]), q),
    then: (resolve: (v: unknown) => unknown) => Promise.resolve({ data: result.data ?? [], error: result.error ?? null }).then(resolve),
  };
  return { client: { from: (t: string) => (calls.push(["from", t]), q) } as never, calls };
}

const rows = [{ template_id: "internal-admin", yaml: "yaml" }];
const okRun = (findings: unknown[] = []) => vi.fn(async () => ({ status: "completed" as const, findings: findings as never, skipped: [] }));

beforeEach(() => gate.mockReset().mockResolvedValue("ok"));

describe("runCustomChecksForOwner", () => {
  it("loads only this owner's enabled checks and runs them against the target", async () => {
    const { client, calls } = db({ data: rows });
    const run = okRun();
    await runCustomChecksForOwner(client, "owner-1", "https://example.com", run);
    expect(calls).toEqual(expect.arrayContaining([["from", "custom_nuclei_templates"], ["owner", "owner-1"], ["enabled", true]]));
    expect(run).toHaveBeenCalledWith("https://example.com", rows);
  });

  it("turns results into findings with a stable per-template check id", async () => {
    const { client } = db({ data: rows });
    const out = await runCustomChecksForOwner(client, "o", "https://example.com", okRun([{ severity: "high", title: "Admin open", detail: "Matched at: https://example.com/a", templateId: "internal-admin" }]));
    expect(out).toEqual([expect.objectContaining({ checkId: "custom-nuclei:internal-admin", severity: "high", title: "[Custom check] Admin open" })]);
  });

  it.each(["denied", "error"])("runs nothing when the plan gate says %s", async (verdict) => {
    gate.mockResolvedValue(verdict);
    const { client } = db({ data: rows });
    const run = okRun();
    expect(await runCustomChecksForOwner(client, "o", "https://example.com", run)).toEqual([]);
    expect(run).not.toHaveBeenCalled();
  });

  it("skips quietly with no checks, and never fails the scan on a load or run error", async () => {
    const none = okRun();
    expect(await runCustomChecksForOwner(db({ data: [] }).client, "o", "https://example.com", none)).toEqual([]);
    expect(none).not.toHaveBeenCalled();
    expect(await runCustomChecksForOwner(db({ error: { message: "boom" } }).client, "o", "https://example.com", none)).toEqual([]);
    const throwing = vi.fn(async () => {
      throw new Error("nuclei exploded");
    });
    expect(await runCustomChecksForOwner(db({ data: rows }).client, "o", "https://example.com", throwing as never)).toEqual([]);
  });
});

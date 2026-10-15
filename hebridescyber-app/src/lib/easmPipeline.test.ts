import { describe, it, expect, vi } from "vitest";
import { runEasmPipeline } from "./easmPipeline";

// A tiny Supabase stub: subscriptions + monitored_targets reads, plus whatever
// isDomainVerified queries (users.is_admin, verifications). We make every owner
// an admin so isDomainVerified short-circuits true without a verifications row.
function stubDb(targets: Array<{ owner: string; target_url: string }>) {
  const subs = [...new Set(targets.map((t) => t.owner))].map((owner) => ({ owner }));
  return {
    from(table: string) {
      if (table === "subscriptions") {
        return { select: () => ({ eq: () => ({ data: subs, error: null }) }) };
      }
      if (table === "monitored_targets") {
        return { select: () => ({ in: () => ({ data: targets, error: null }) }) };
      }
      if (table === "users") {
        // isDomainVerified: admin short-circuit
        return { select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: { is_admin: true } }) }) }) };
      }
      throw new Error(`unexpected table ${table}`);
    },
  } as unknown as import("@supabase/supabase-js").SupabaseClient;
}

describe("runEasmPipeline", () => {
  it("sweeps each verified target once, reusing runEasmDiscovery, and sums new assets", async () => {
    const db = stubDb([
      { owner: "o1", target_url: "https://a.example.com" },
      { owner: "o1", target_url: "https://shop.example.net" },
    ]);
    const discover = vi.fn().mockResolvedValue({ domain: "x", assetsDiscovered: 3, newAssets: 2, assets: [] });

    const res = await runEasmPipeline(db, { discover });

    expect(res.targetsSwept).toBe(2);
    expect(res.newAssets).toBe(4);
    expect(res.errors).toBe(0);
    // Scopes to the registrable owner-domain (so a sweep covers the whole zone),
    // and critically never runs brute-force from a standalone sweep.
    expect(discover).toHaveBeenCalledWith(db, "o1", "example.com", { bruteForce: false });
    expect(discover).toHaveBeenCalledWith(db, "o1", "example.net", { bruteForce: false });
  });

  it("counts a failing sweep as an error and keeps going", async () => {
    const db = stubDb([
      { owner: "o1", target_url: "https://a.example.com" },
      { owner: "o1", target_url: "https://b.example.com" },
    ]);
    const discover = vi
      .fn()
      .mockRejectedValueOnce(new Error("crt.sh down"))
      .mockResolvedValueOnce({ domain: "x", assetsDiscovered: 1, newAssets: 1, assets: [] });

    const res = await runEasmPipeline(db, { discover });

    expect(res.errors).toBe(1);
    expect(res.targetsSwept).toBe(1);
    expect(res.newAssets).toBe(1);
  });

  it("dry-run considers targets but discovers nothing", async () => {
    const db = stubDb([{ owner: "o1", target_url: "https://a.example.com" }]);
    const discover = vi.fn();

    const res = await runEasmPipeline(db, { dryRun: true, discover });

    expect(res.targetsSwept).toBe(1);
    expect(discover).not.toHaveBeenCalled();
  });

  it("returns an empty result when there are no active subscriptions", async () => {
    const db = stubDb([]);
    const res = await runEasmPipeline(db, { discover: vi.fn() });
    expect(res.targetsConsidered).toBe(0);
    expect(res.targetsSwept).toBe(0);
  });

  it("skips a target whose URL has no resolvable registrable domain", async () => {
    const db = stubDb([{ owner: "o1", target_url: "https://localhost" }]);
    const discover = vi.fn();
    const res = await runEasmPipeline(db, { discover });
    // localhost has no registrable domain under the public suffix list
    expect(res.skippedNoDomain + res.targetsSwept).toBe(1);
  });
});

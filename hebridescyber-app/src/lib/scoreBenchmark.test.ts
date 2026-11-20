import { afterEach, describe, expect, it, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { MIN_GROUP, benchmarkFrom, benchmarkSentence, freeCheckBenchmark, isBenchmarkEnabled, recordFreeCheckScore, scanBenchmark } from "./scoreBenchmark";

afterEach(() => vi.unstubAllEnvs());

describe("isBenchmarkEnabled", () => {
  it("is on only for exactly \"true\"", () => {
    expect(isBenchmarkEnabled({})).toBe(false);
    expect(isBenchmarkEnabled({ SCORE_BENCHMARK_ENABLED: "1" })).toBe(false);
    expect(isBenchmarkEnabled({ SCORE_BENCHMARK_ENABLED: "true" })).toBe(true);
  });
});

describe("benchmarkFrom", () => {
  it("gives the share that scored lower, rounded down", () => {
    expect(benchmarkFrom({ total: 200, lower: 125 }, "scan")).toEqual({ betterThanPercent: 62, groupSize: 200, windowDays: 90, kind: "scan" });
  });

  it("shows nothing below the minimum group or for nonsense counts", () => {
    expect(benchmarkFrom({ total: MIN_GROUP - 1, lower: 10 }, "scan")).toBeNull();
    expect(benchmarkFrom({ total: 100, lower: 101 }, "scan")).toBeNull();
    expect(benchmarkFrom({ total: 100, lower: -1 }, "scan")).toBeNull();
    expect(benchmarkFrom(null, "scan")).toBeNull();
  });
});

describe("benchmarkSentence", () => {
  it("says which group, never a national or industry claim", () => {
    expect(benchmarkSentence({ betterThanPercent: 62, groupSize: 1240, windowDays: 90, kind: "free_check" })).toBe("Better than 62% of the 1,240 sites given this free check in the last 90 days.");
    expect(benchmarkSentence({ betterThanPercent: 40, groupSize: 80, windowDays: 90, kind: "scan" })).toBe("Better than 40% of the 80 sites scanned with Hebrides Cyber in the last 90 days.");
    expect(benchmarkSentence({ betterThanPercent: 0, groupSize: 80, windowDays: 90, kind: "scan" })).toBe("Lower than the other 80 sites scanned with Hebrides Cyber in the last 90 days.");
  });
});

describe("loaders", () => {
  const db = (rpcResult: unknown, insert = vi.fn().mockResolvedValue({ error: null })) =>
    ({ rpc: vi.fn().mockResolvedValue(rpcResult), from: () => ({ insert }) }) as unknown as SupabaseClient & { rpc: ReturnType<typeof vi.fn> };

  it("do nothing while the feature is off", async () => {
    const d = db({ data: [{ total: 500, lower: 100 }], error: null });
    expect(await freeCheckBenchmark(d, 70)).toBeNull();
    expect(await scanBenchmark(d, 70, "o1")).toBeNull();
    await recordFreeCheckScore(d, 70);
    expect(d.rpc).not.toHaveBeenCalled();
  });

  it("when on, read counts (excluding the owner's own sites for scans) and record a clamped score", async () => {
    vi.stubEnv("SCORE_BENCHMARK_ENABLED", "true");
    const insert = vi.fn().mockResolvedValue({ error: null });
    const d = db({ data: [{ total: "500", lower: "100" }], error: null }, insert);
    expect(await scanBenchmark(d, 70.4, "o1")).toMatchObject({ betterThanPercent: 20, groupSize: 500, kind: "scan" });
    expect(d.rpc).toHaveBeenCalledWith("scan_score_counts", { p_score: 70, p_days: 90, p_exclude_owner: "o1" });
    await recordFreeCheckScore(d, 140);
    expect(insert).toHaveBeenCalledWith({ score: 100 });
  });

  it("when on, a database error means no benchmark, never a wrong one", async () => {
    vi.stubEnv("SCORE_BENCHMARK_ENABLED", "true");
    expect(await freeCheckBenchmark(db({ data: null, error: { message: "function does not exist" } }), 70)).toBeNull();
  });
});

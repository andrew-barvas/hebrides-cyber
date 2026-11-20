import { describe, expect, it } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { buildReportTrends, formatChange, loadReportTrends, loadScoreHistory, renderTrendSvg, scoreAt, type ScorePoint } from "./reportTrends";

const p = (at: string, score: number): ScorePoint => ({ at, score });

describe("scoreAt", () => {
  it("is the latest score at or before the time, or null before any scan", () => {
    const pts = [p("2026-10-01T10:00:00Z", 60), p("2026-10-15T10:00:00Z", 70)];
    expect(scoreAt(pts, Date.parse("2026-09-30T00:00:00Z"))).toBeNull();
    expect(scoreAt(pts, Date.parse("2026-10-10T00:00:00Z"))).toBe(60);
    expect(scoreAt(pts, Date.parse("2026-10-15T10:00:00Z"))).toBe(70);
  });
});

describe("buildReportTrends", () => {
  const history = new Map<string, ScorePoint[]>([
    ["shop.example.com", [p("2026-09-20T09:00:00Z", 50), p("2026-10-10T09:00:00Z", 65), p("2026-10-28T09:00:00Z", 80)]],
    ["new.example.com", [p("2026-10-20T09:00:00Z", 90)]],
    ["later.example.com", [p("2026-11-05T09:00:00Z", 40)]],
  ]);

  it("measures each site from its score before the period (or its first in it) to its last by the end", () => {
    const t = buildReportTrends(history, "2026-10-01", "2026-10-31");
    expect(t.available).toBe(true);
    expect(t.sites).toEqual([
      { host: "new.example.com", start: 90, end: 90, change: 0 },
      { host: "shop.example.com", start: 50, end: 80, change: 30 },
    ]);
  });

  it("averages week by week only across sites scanned by then, ending on the period's last day", () => {
    const t = buildReportTrends(history, "2026-10-01", "2026-10-31");
    expect(t.average[0]).toEqual({ at: "2026-10-07", score: 50 });
    expect(t.average.at(-1)).toEqual({ at: "2026-10-31", score: 85 });
  });

  it("is unavailable for a bad period or no history", () => {
    expect(buildReportTrends(history, "2026-11-30", "2026-10-01").available).toBe(false);
    expect(buildReportTrends(new Map(), "2026-10-01", "2026-10-31")).toEqual({ available: false, sites: [], average: [] });
  });
});

describe("formatChange", () => {
  it("reads naturally", () => {
    expect(formatChange(12)).toBe("+12");
    expect(formatChange(-5)).toBe("−5");
    expect(formatChange(0)).toBe("no change");
    expect(formatChange(null)).toBe("—");
  });
});

describe("renderTrendSvg", () => {
  it("draws a fixed 0–100 chart from numbers and dates only", () => {
    const svg = renderTrendSvg([p("2026-10-07", 50), p("2026-10-31", 85)], { label: "average" });
    expect(svg.startsWith("<svg")).toBe(true);
    expect(svg).toContain('aria-label="Average security score over time, from 50 to 85"');
    expect(svg).toContain(">2026-10-07<");
    expect(svg).toContain("<polyline");
  });

  it("is empty with fewer than two points, and never interpolates a non-date", () => {
    expect(renderTrendSvg([p("2026-10-07", 50)])).toBe("");
    const svg = renderTrendSvg([p("2026-10-07<script>", 50), p("2026-10-08", 60)]);
    expect(svg).not.toContain("<script>");
  });
});

describe("loadScoreHistory", () => {
  const db = (tables: Record<string, { data: unknown; error: unknown }>) =>
    ({
      from: (table: string) => {
        const q: Record<string, unknown> = {};
        for (const m of ["select", "eq", "gte", "lte", "order", "limit", "in"]) q[m] = () => q;
        q.then = (r: (v: unknown) => void) => r(tables[table] ?? { data: [], error: null });
        return q;
      },
    }) as unknown as SupabaseClient;

  it("groups monitored sites' scored scans by host and skips unscored ones", async () => {
    const history = await loadScoreHistory(
      db({
        monitored_targets: { data: [{ target_url: "https://shop.example.com" }], error: null },
        scans: { data: [{ id: "s1", target_url: "https://shop.example.com/", created_at: "2026-10-10T00:00:00Z" }, { id: "s2", target_url: "https://other.example.com", created_at: "2026-10-11T00:00:00Z" }, { id: "s3", target_url: "https://shop.example.com", created_at: "2026-10-12T00:00:00Z" }], error: null },
        scan_results: { data: [{ scan_id: "s1", score: 70 }, { scan_id: "s2", score: 10 }, { scan_id: "s3", score: null }], error: null },
      }),
      "o",
      new Date("2026-09-01T00:00:00Z"),
      new Date("2026-11-01T00:00:00Z")
    );
    expect(history).toEqual(new Map([["shop.example.com", [{ at: "2026-10-10T00:00:00Z", score: 70 }]]]));
  });

  it("ignores scans whose address can't be parsed, and counts every host when nothing is monitored", async () => {
    const history = await loadScoreHistory(
      db({
        monitored_targets: { data: [], error: null },
        scans: { data: [{ id: "s1", target_url: "http://[bad", created_at: "2026-10-10T00:00:00Z" }, { id: "s2", target_url: "other.example.com", created_at: "2026-10-11T00:00:00Z" }], error: null },
        scan_results: { data: [{ scan_id: "s1", score: 50 }, { scan_id: "s2", score: 60 }], error: null },
      }),
      "o",
      new Date("2026-09-01T00:00:00Z"),
      new Date("2026-11-01T00:00:00Z")
    );
    expect(history).toEqual(new Map([["other.example.com", [{ at: "2026-10-11T00:00:00Z", score: 60 }]]]));
  });

  it("is null on a read failure, and loadReportTrends then reports no trend", async () => {
    const broken = db({ scans: { data: null, error: { message: "boom" } } });
    expect(await loadScoreHistory(broken, "o", new Date(), new Date())).toBeNull();
    expect(await loadReportTrends(broken, "o", "2026-10-01", "2026-10-31")).toEqual({ available: false, sites: [], average: [] });
  });
});

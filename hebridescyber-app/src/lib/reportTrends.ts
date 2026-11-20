// Score trends for reports (COMPETITOR-ANALYSIS-ENTERPRISE-2026-11.md idea 7):
// how each site's score moved over a report's period, and the average across
// sites week by week. Ratings vendors lead with history because it's what a
// renewal rests on: "are we getting better?". Used by the Lookout report
// (page and PDF) and the Agency portfolio PDF.
//
// A site's score at a date is its latest completed scan's score on or before
// that date (scores only change when a scan runs). A site with no scan by a
// date is left out of that week's average rather than counted as 0, and a
// site with no scan before the period starts takes its first score in the
// period as its starting point, so a new site never shows as a big jump.
//
// renderTrendSvg returns an inline SVG built only from numbers and fixed
// strings, so it is safe in report HTML and fetches nothing.
import type { SupabaseClient } from "@supabase/supabase-js";

export type ScorePoint = { at: string; score: number };
export type SiteTrend = { host: string; start: number | null; end: number | null; change: number | null };
export type ReportTrends = { available: boolean; sites: SiteTrend[]; average: ScorePoint[] };

const DAY_MS = 24 * 60 * 60 * 1000;
const WEEK_MS = 7 * DAY_MS;
const MAX_SCANS = 3000;
const ID_CHUNK = 200;

function endOfDay(date: string): number {
  return Date.parse(`${date.slice(0, 10)}T23:59:59.999Z`);
}

function sorted(points: readonly ScorePoint[]): ScorePoint[] {
  return points.filter((p) => Number.isFinite(p.score) && !Number.isNaN(Date.parse(p.at))).sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
}

/** Pure. The latest score at or before `t` (ms), or null. Points must be sorted. */
export function scoreAt(points: readonly ScorePoint[], t: number): number | null {
  let out: number | null = null;
  for (const p of points) {
    if (Date.parse(p.at) > t) break;
    out = p.score;
  }
  return out;
}

/** Pure. Per-site start, end and change over [periodStart, periodEnd] (dates or ISO), and the weekly average. */
export function buildReportTrends(history: ReadonlyMap<string, readonly ScorePoint[]>, periodStart: string, periodEnd: string): ReportTrends {
  const startMs = Date.parse(`${periodStart.slice(0, 10)}T00:00:00Z`);
  const endMs = endOfDay(periodEnd);
  if (Number.isNaN(startMs) || Number.isNaN(endMs) || endMs < startMs) return { available: false, sites: [], average: [] };

  const series = new Map<string, ScorePoint[]>();
  for (const [host, pts] of history) series.set(host, sorted(pts));

  const sites: SiteTrend[] = [];
  for (const [host, pts] of series) {
    const end = scoreAt(pts, endMs);
    if (end === null) continue;
    const before = scoreAt(pts, startMs - 1);
    const firstInPeriod = pts.find((p) => Date.parse(p.at) >= startMs && Date.parse(p.at) <= endMs)?.score ?? null;
    const start = before ?? firstInPeriod;
    sites.push({ host, start, end, change: start === null ? null : end - start });
  }
  sites.sort((a, b) => (a.change ?? 0) - (b.change ?? 0) || a.host.localeCompare(b.host));

  const average: ScorePoint[] = [];
  const ticks: number[] = [];
  for (let t = startMs + WEEK_MS - 1; t < endMs; t += WEEK_MS) ticks.push(t);
  ticks.push(endMs);
  for (const t of ticks) {
    const scores = [...series.values()].map((pts) => scoreAt(pts, t)).filter((s): s is number => s !== null);
    if (scores.length) average.push({ at: new Date(Math.min(t, endMs)).toISOString().slice(0, 10), score: Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) });
  }

  return { available: sites.length > 0, sites, average };
}

/** Pure. "+12", "−5", "no change", or "—" when unknown. */
export function formatChange(change: number | null): string {
  if (change === null) return "—";
  if (change === 0) return "no change";
  return change > 0 ? `+${change}` : `−${Math.abs(change)}`;
}

/**
 * Pure. A small score-over-time chart (0–100, fixed scale) as inline SVG, or
 * "" with fewer than two points. Only numbers and ISO dates (validated) are
 * interpolated.
 */
export function renderTrendSvg(points: readonly ScorePoint[], opts: { width?: number; height?: number; label?: string } = {}): string {
  const pts = sorted(points);
  if (pts.length < 2) return "";
  const width = opts.width ?? 520;
  const height = opts.height ?? 120;
  const padX = 34;
  const padY = 14;
  const innerW = width - padX - 10;
  const innerH = height - padY * 2;
  const x = (i: number) => (padX + (i / (pts.length - 1)) * innerW).toFixed(1);
  const y = (s: number) => (padY + innerH - (Math.max(0, Math.min(100, s)) / 100) * innerH).toFixed(1);
  const line = pts.map((p, i) => `${x(i)},${y(p.score)}`).join(" ");
  const date = (iso: string) => (/^\d{4}-\d{2}-\d{2}/.test(iso) ? iso.slice(0, 10) : "");
  const grid = [0, 50, 75, 90, 100]
    .map((g) => `<line x1="${padX}" x2="${width - 10}" y1="${y(g)}" y2="${y(g)}" stroke="#e4e9ee" stroke-width="1"/><text x="${padX - 6}" y="${(Number(y(g)) + 3).toFixed(1)}" font-size="9" text-anchor="end" fill="#64748b">${g}</text>`)
    .join("");
  const first = pts[0];
  const last = pts[pts.length - 1];
  const title = opts.label === "average" ? "Average security score over time" : "Security score over time";
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height + 14}" viewBox="0 0 ${width} ${height + 14}" role="img" aria-label="${title}, from ${first.score} to ${last.score}">${grid}<polyline points="${line}" fill="none" stroke="#0b3d5b" stroke-width="2"/>${pts
    .map((p, i) => `<circle cx="${x(i)}" cy="${y(p.score)}" r="2.5" fill="#0b3d5b"/>`)
    .join("")}<text x="${padX}" y="${height + 10}" font-size="9" fill="#64748b">${date(first.at)}</text><text x="${width - 10}" y="${height + 10}" font-size="9" text-anchor="end" fill="#64748b">${date(last.at)}</text></svg>`;
}

function hostOfUrl(url: string): string | null {
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Each monitored site's completed-scan scores from `since` to `until` (the
 * owner's monitored sites only; every scanned host when they have none).
 * Null on a read failure, so callers leave the trend out rather than show a
 * wrong one.
 */
export async function loadScoreHistory(db: SupabaseClient, ownerId: string, since: Date, until: Date): Promise<Map<string, ScorePoint[]> | null> {
  const [targets, scans] = await Promise.all([
    db.from("monitored_targets").select("target_url").eq("owner", ownerId),
    db
      .from("scans")
      .select("id, target_url, created_at")
      .eq("owner", ownerId)
      .eq("status", "completed")
      .gte("created_at", since.toISOString())
      .lte("created_at", until.toISOString())
      .order("created_at", { ascending: false })
      .limit(MAX_SCANS),
  ]);
  if (targets.error || scans.error) return null;

  const monitored = new Set(((targets.data ?? []) as Array<{ target_url: string }>).map((t) => hostOfUrl(t.target_url)).filter((h): h is string => Boolean(h)));
  const rows = ((scans.data ?? []) as Array<{ id: string; target_url: string; created_at: string }>)
    .map((s) => ({ ...s, host: hostOfUrl(s.target_url) }))
    .filter((s): s is typeof s & { host: string } => Boolean(s.host) && (monitored.size === 0 || monitored.has(s.host as string)));

  const scoreById = new Map<string, number>();
  const ids = rows.map((r) => r.id);
  for (let i = 0; i < ids.length; i += ID_CHUNK) {
    const { data, error } = await db.from("scan_results").select("scan_id, score").in("scan_id", ids.slice(i, i + ID_CHUNK));
    if (error) return null;
    for (const r of (data ?? []) as Array<{ scan_id: string; score: unknown }>) {
      if (typeof r.score === "number" && Number.isFinite(r.score)) scoreById.set(r.scan_id, r.score);
    }
  }

  const history = new Map<string, ScorePoint[]>();
  for (const r of rows) {
    const score = scoreById.get(r.id);
    if (score === undefined) continue;
    const list = history.get(r.host) ?? [];
    list.push({ at: r.created_at, score });
    history.set(r.host, list);
  }
  return history;
}

/** Loads history from 90 days before the period (for each site's starting score) to its end, and builds the trends. Never throws. */
export async function loadReportTrends(db: SupabaseClient, ownerId: string, periodStart: string, periodEnd: string): Promise<ReportTrends> {
  try {
    const startMs = Date.parse(`${periodStart.slice(0, 10)}T00:00:00Z`);
    const endMs = endOfDay(periodEnd);
    if (Number.isNaN(startMs) || Number.isNaN(endMs)) return { available: false, sites: [], average: [] };
    const history = await loadScoreHistory(db, ownerId, new Date(startMs - 90 * DAY_MS), new Date(endMs));
    return history ? buildReportTrends(history, periodStart, periodEnd) : { available: false, sites: [], average: [] };
  } catch {
    return { available: false, sites: [], average: [] };
  }
}

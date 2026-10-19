// Page discovery with katana (ProjectDiscovery, MIT,
// https://github.com/projectdiscovery/katana), then the E-70 crawler's own
// page checks on what it found. katana reads JavaScript files for routes
// (`-jc`), so it reaches pages the anonymous crawler can't: client-side
// routes and endpoints only mentioned in a bundle.
//
// Why its own tool and namespace (`katana.*`), not seeds for the base crawl:
// katana only exists on the scheduled worker. If it seeded `crawl.*`, every
// passive on-demand scan (which can't visit those pages) would mark their
// findings fixed and the next scheduled scan would reopen them. Under
// `katana.*` a finding is resolved only by a scan where katana itself ran
// (findingLifecycle.ts keys coverage by tool).
//
// Behaviour checked against the real v1.8.0 binary (see the integration test):
//   - `-ob` (omit body) also switches off JS endpoint extraction, so plain URL
//     output is used instead of JSONL (which would carry every body);
//   - `-kf` takes ONE value (`all`), and a flag error is printed on stdout
//     with exit 2 — any non-URL output line is therefore an error;
//   - an unreachable target still prints its own URL and exits 0, so the
//     wrapper fetches the target itself first (unreachable → "error");
//   - without `-cos`, katana follows `/logout` links: we always pass the
//     crawler's action-link pattern (ACTION_URL_PATTERN);
//   - katana doesn't honour robots.txt (no such option) and fetches robots.txt
//     and sitemap.xml with its default browser user agent; its crawl requests
//     carry ours. The page checks themselves go through checkCrawl, which
//     applies robots.txt, the action-link rules and the page cap.
//   - stdin must be closed (execTool does) or katana waits on it.
import { execTool } from "../../lib/execTool";
import type { Finding } from "../../lib/scanners";
import { ACTION_URL_PATTERN, CRAWLER_USER_AGENT, checkCrawl, isSameSite, normaliseUrl, skipReason, urlKey, type CrawlResult } from "../../lib/scanners/crawler";
import { buildCrawlFindings } from "../../lib/scanners/crawlFindings";

const PROBE_TIMEOUT_MS = 15_000;
/** katana's own -ct budget; the process timeout adds headroom for shutdown. */
const CRAWL_SECONDS = 60;
const PROCESS_TIMEOUT_MS = (CRAWL_SECONDS + 30) * 1000;
/** Pages katana found that get the page checks. */
export const KATANA_MAX_PAGES = 30;
const PAGE_BUDGET_MS = 40_000;
const FILTERED_EXTENSIONS = "png,jpg,jpeg,gif,svg,ico,webp,avif,bmp,css,woff,woff2,ttf,eot,otf,mp3,mp4,webm,mov,avi,pdf,zip,gz,tgz,rar,7z,map";

export type KatanaResult =
  | {
      /** "partial" when the page checks didn't finish (throttled, budget): not-run for lifecycle. */
      status: "completed" | "partial";
      /** Same-site URLs katana discovered (start page excluded). */
      discovered: number;
      /** Pages the base crawl hadn't visited, which got the page checks. */
      newPages: string[];
      crawl: CrawlResult;
      findings: Finding[];
      note?: string;
    }
  | { status: "not_configured" | "error"; findings: []; note: string };

function katanaBinary(): string {
  return process.env.KATANA_BIN || "katana";
}

export function buildKatanaArgs(targetUrl: string): string[] {
  return [
    "-u", targetUrl,
    "-d", "3",
    "-jc",
    "-kf", "all",
    "-fs", "fqdn",
    "-ct", `${CRAWL_SECONDS}s`,
    "-c", "5",
    "-p", "1",
    "-rl", "10",
    "-timeout", "10",
    "-retry", "1",
    "-duc",
    "-silent",
    "-nc",
    "-H", `User-Agent: ${CRAWLER_USER_AGENT}`,
    "-cos", ACTION_URL_PATTERN,
    "-ef", FILTERED_EXTENSIONS,
  ];
}

/** One URL per line. Throws on anything else (katana prints flag errors on stdout). */
export function parseKatanaOutput(stdout: string): string[] {
  const urls: string[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let url: URL;
    try {
      url = new URL(trimmed);
    } catch {
      throw new Error(`unexpected katana output: ${trimmed.slice(0, 200)}`);
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error(`unexpected katana output: ${trimmed.slice(0, 200)}`);
    urls.push(url.href);
  }
  return urls;
}

/**
 * Same-site pages worth checking that the base crawl didn't already visit,
 * in katana's order, capped. Assets, action links and the start page drop out.
 */
export function selectNewPages(discovered: string[], targetUrl: string, alreadyCrawled: string[], max = KATANA_MAX_PAGES): string[] {
  const start = normaliseUrl(targetUrl, targetUrl);
  if (!start) return [];
  const seen = new Set<string>([urlKey(start), ...alreadyCrawled.map((u) => normaliseUrl(u, u)).filter((u): u is URL => u !== null).map(urlKey)]);
  const out: string[] = [];
  for (const raw of discovered) {
    const url = normaliseUrl(raw, targetUrl);
    if (!url || !isSameSite(url, start) || skipReason(url)) continue;
    const key = urlKey(url);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(url.href);
    if (out.length >= max) break;
  }
  return out;
}

/** The crawler's findings for katana's pages, in the katana.* namespace. */
export function buildKatanaFindings(crawl: CrawlResult): Finding[] {
  return buildCrawlFindings(crawl).map((f) => ({
    ...f,
    checkId: f.checkId?.replace(/^crawl\./, "katana."),
    title: `${f.title} (pages found by katana)`,
  }));
}

type ExecFailure = { code?: string | number; killed?: boolean; message?: string; stderr?: string };

/** Never throws. No binary → not_configured; unreachable target, tool failure or bad output → error. */
export async function runKatana(targetUrl: string, alreadyCrawled: string[] = []): Promise<KatanaResult> {
  try {
    await execTool(katanaBinary(), ["-version"], { timeout: PROBE_TIMEOUT_MS, maxBuffer: 1024 * 1024 });
  } catch (err) {
    const failure = err as ExecFailure;
    if (failure.code === "ENOENT") {
      return { status: "not_configured", findings: [], note: "katana is not installed in this environment — skipping JavaScript-aware page discovery." };
    }
    return { status: "error", findings: [], note: `katana -version failed: ${(failure.message ?? "unknown error").slice(0, 300)}` };
  }

  // katana prints the input URL and exits 0 even when it can't connect.
  try {
    const res = await fetch(targetUrl, { headers: { "User-Agent": CRAWLER_USER_AGENT }, signal: AbortSignal.timeout(15_000) });
    await res.body?.cancel();
  } catch (err) {
    return { status: "error", findings: [], note: `Target unreachable, so katana's output would mean nothing: ${(err as Error).message}` };
  }

  let stdout: string;
  try {
    ({ stdout } = await execTool(katanaBinary(), buildKatanaArgs(targetUrl), { timeout: PROCESS_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }));
  } catch (err) {
    const failure = err as ExecFailure;
    if (failure.killed) return { status: "error", findings: [], note: `katana exceeded ${PROCESS_TIMEOUT_MS / 1000}s` };
    const why = (failure.stderr || failure.message || "unknown error").replace(/\s+/g, " ").slice(0, 300);
    return { status: "error", findings: [], note: `katana failed (exit ${String(failure.code ?? "?")}): ${why}` };
  }

  let urls: string[];
  try {
    urls = parseKatanaOutput(stdout);
  } catch (err) {
    return { status: "error", findings: [], note: (err as Error).message };
  }

  const start = normaliseUrl(targetUrl, targetUrl);
  const discovered = start ? urls.filter((u) => urlKey(new URL(u)) !== urlKey(start)).length : urls.length;
  const newPages = selectNewPages(urls, targetUrl, alreadyCrawled);
  const crawl = await checkCrawl(targetUrl, { onlyUrls: newPages, maxPages: KATANA_MAX_PAGES + 1, budgetMs: PAGE_BUDGET_MS });
  if (crawl.status === "error") return { status: "error", findings: [], note: `katana found ${discovered} URL(s), but its pages couldn't be checked: ${crawl.note}` };

  const findings = buildKatanaFindings(crawl);
  if (crawl.status === "partial") {
    return { status: "partial", discovered, newPages, crawl, findings, note: crawl.note ?? "The page checks didn't finish." };
  }
  return { status: "completed", discovered, newPages, crawl, findings };
}

// Content discovery via ffuf — the Tier A offensive suite's bounded
// directory/path brute-force.
//
// This IS a brute-force (it requests paths the site never linked), which is why
// it is offensive-only: it runs under the `offensive` scan profile, which the
// worker unlocks only for a Tier A owner with a per-scan authorization against
// an ownership-verified domain (run-queued-scan-jobs.ts). It stays deliberately
// bounded — a small CURATED wordlist (common sensitive dirs/files, not a
// mega-list), a hard request-rate cap, autocalibration to drop SPA catch-all
// 200s, and a wall-clock cap — so it probes readiness without hammering the
// target. Read-only GETs, no payloads.
//
// Targets are built as <target>/FUZZ; ffuf writes a JSON results file we read
// back (same temp-file pattern as arjun.ts). The wordlist path comes from
// CONTENT_DISCOVERY_WORDLIST (the scheduled-scans/tool-integration workflow
// points it at src/worker/tools/wordlists/content-dirs.txt); without it, or
// without the ffuf binary, the tool no-ops with { status: "not_configured" }.
//
// Parsing follows real ffuf v2.1.0 `-of json` output (fixture
// fixtures/ffuf/): { results: [{ input: { FUZZ }, status, length, url,
// "content-type" }, …] }.

import { execTool } from "../../lib/execTool";
import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Finding } from "../../lib/scanners/index";
import { CONTENT_DISCOVERY_FOUND } from "../../lib/scanners/remediationText";

const FFUF_TIMEOUT_MS = 180_000;
// A curated wordlist can still hit many paths on a busy site; cap the per-path
// rows and roll the rest into one summary, like subdomains/httpx.
const MAX_HIT_FINDINGS = 25;
// ffuf's own wall-clock budget, below our hard kill so it exits cleanly with
// the results it already has rather than being SIGTERM'd empty.
const FFUF_MAXTIME_S = 120;
const FFUF_RATE = "20"; // requests/sec cap — bounded, not a flood
const FFUF_THREADS = "10";

export type ContentDiscoveryHit = {
  path: string;
  url: string;
  status: number;
  length: number;
  contentType: string;
};

export type ContentDiscoveryResult =
  | { status: "completed"; hits: ContentDiscoveryHit[] }
  | { status: "not_configured" }
  | { status: "error"; note: string };

type FfufResultEntry = {
  input?: { FUZZ?: string };
  status?: number;
  length?: number;
  url?: string;
  "content-type"?: string;
};

/** Pure: ffuf's `-of json` file contents to deduplicated discovered paths. */
export function parseFfufOutput(json: string): ContentDiscoveryHit[] {
  let parsed: { results?: FfufResultEntry[] };
  try {
    parsed = JSON.parse(json);
  } catch {
    return [];
  }
  const hits: ContentDiscoveryHit[] = [];
  const seen = new Set<string>();
  for (const entry of parsed.results ?? []) {
    if (!entry.url || typeof entry.status !== "number") continue;
    if (seen.has(entry.url)) continue;
    seen.add(entry.url);
    hits.push({
      path: entry.input?.FUZZ ?? "",
      url: entry.url,
      status: entry.status,
      length: typeof entry.length === "number" ? entry.length : 0,
      contentType: entry["content-type"] ?? "",
    });
  }
  return hits;
}

// A path that cannot exist, used to learn a catch-all's response. Fixed (not
// random) so the behaviour is deterministic and testable.
const PROBE_PATH = "hc-content-discovery-probe-x9f2a7";

/**
 * Returns the body length of the site's response to a definitely-missing path
 * when the site answers it as "success" (status < 400) — i.e. a catch-all / SPA
 * shell that would otherwise make every wordlist entry look like a hit. Returns
 * null for a normal not-found (the common case) or on any error, so calibration
 * never blocks the scan.
 */
export async function calibrateCatchAll(base: string): Promise<number | null> {
  try {
    const res = await fetch(`${base}/${PROBE_PATH}`, { redirect: "manual", signal: AbortSignal.timeout(8000) });
    if (res.status >= 400) return null; // normal not-found — no catch-all to filter
    const body = await res.text();
    return body.length;
  } catch {
    return null;
  }
}

export async function runContentDiscovery(targetUrl: string): Promise<ContentDiscoveryResult> {
  const wordlist = process.env.CONTENT_DISCOVERY_WORDLIST;
  if (!wordlist) return { status: "not_configured" };

  let base: string;
  try {
    base = new URL(targetUrl).origin;
  } catch {
    return { status: "error", note: "Invalid URL" };
  }

  // Catch-all calibration, our own rather than ffuf's `-ac` (which proved
  // non-deterministic — it filtered a real endpoint and surfaced its own
  // calibration probe as a false hit). Fetch a path that cannot exist; if the
  // site answers "success" to it, it is a catch-all/SPA that returns its shell
  // for everything, so we tell ffuf to filter that exact response size (`-fs`)
  // and only genuinely-distinct paths survive. A normal 404 means no filter.
  const catchAllSize = await calibrateCatchAll(base);

  const outFile = join(tmpdir(), `ffuf-${Date.now()}-${process.pid}.json`);
  try {
    await execTool(
      "ffuf",
      [
        "-w", wordlist,
        "-u", `${base}/FUZZ`,
        "-of", "json",
        "-o", outFile,
        "-s", // quiet; results go to the file
        ...(catchAllSize !== null ? ["-fs", String(catchAllSize)] : []),
        "-rate", FFUF_RATE,
        "-t", FFUF_THREADS,
        "-timeout", "10",
        "-maxtime", String(FFUF_MAXTIME_S),
      ],
      { timeout: FFUF_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }
    );
    const raw = await readFile(outFile, "utf8").catch(() => "");
    return { status: "completed", hits: parseFfufOutput(raw) };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") return { status: "not_configured" };
    // ffuf may exit non-zero yet still have written the results it found.
    const raw = await readFile(outFile, "utf8").catch(() => "");
    if (raw.trim().length > 0) return { status: "completed", hits: parseFfufOutput(raw) };
    return { status: "error", note: `ffuf exited with error: ${error.message}` };
  } finally {
    rm(outFile, { force: true }).catch(() => undefined);
  }
}

/**
 * Findings for the discovered paths. Each is `low` (a reachable unlinked path
 * is worth confirming, not inherently a vulnerability), keyed by path so it
 * rides findingsDiff.ts (a newly-reachable admin/backup path shows up as NEW).
 * Sorted + capped so the cap doesn't flap hosts between NEW and FIXED.
 */
export function buildContentDiscoveryFindings(hits: ContentDiscoveryHit[]): Finding[] {
  const sorted = [...hits].sort((a, b) => a.url.localeCompare(b.url));
  const findings: Finding[] = [];
  const listed = sorted.slice(0, MAX_HIT_FINDINGS);
  for (const h of listed) {
    findings.push({
      checkId: `content-discovery.found:${h.path}`,
      severity: "low",
      title: `Unlinked path reachable: /${h.path}`,
      detail: `${h.url} responded ${h.status}${h.contentType ? ` (${h.contentType})` : ""}. Found by content discovery (ffuf) probing a curated path list — it is not linked from the site. Confirm it is meant to be reachable.`,
      remediation: CONTENT_DISCOVERY_FOUND,
    });
  }
  const remaining = sorted.length - listed.length;
  if (remaining > 0) {
    findings.push({
      checkId: "content-discovery.found-additional",
      severity: "info",
      title: `${remaining} further unlinked path(s) not listed individually`,
      detail: `Content discovery found ${sorted.length} reachable paths; the first ${MAX_HIT_FINDINGS} are listed above.`,
      remediation: CONTENT_DISCOVERY_FOUND,
    });
  }
  return findings;
}

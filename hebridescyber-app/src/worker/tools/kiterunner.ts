// Kiterunner (`kr`) integration: contextual API-route discovery. Kiterunner
// sends a curated, Swagger-derived wordlist of API paths — with the method,
// headers and body each route expects — to find endpoints that aren't linked
// from the page or its JavaScript. It runs only on ownership-verified
// domains, like every other active tool here, and reads (never writes) each
// route it probes.
//
// Two things must be present or the tool no-ops with { status: "not_configured" }:
//   - the `kr` binary (pinned v1.0.2 in scheduled-scans.yml);
//   - a compiled `.kite` wordlist, whose path is KITERUNNER_WORDLIST. The
//     workload wordlist lives on Assetnote's CDN; the workflow downloads and
//     checksums it, rather than letting `kr` fetch it at scan time (keeps the
//     "pin every external asset" rule and avoids a network dependency mid-scan).
//
// Parsing follows real kiterunner v1.0.2 `-o json -q` output (captured in
// fixtures/kiterunner/): one JSON object per discovered route,
// {method, path, responses:[{sc, len}], …}. `--fail-status-codes 404,429`
// drops the misses, so only real endpoints are emitted; the two-phase scan
// can repeat a route, so we dedupe by method+path.

import { execTool } from "../../lib/execTool";

const KITERUNNER_TIMEOUT_MS = 180_000;

export type KiterunnerEndpoint = {
  method: string;
  path: string;
  statusCode: number;
  contentLength: number;
};

export type KiterunnerResult =
  | { status: "completed"; endpoints: KiterunnerEndpoint[] }
  | { status: "not_configured" }
  | { status: "error"; note: string };

type KiterunnerLine = {
  method?: string;
  path?: string;
  responses?: Array<{ sc?: number; len?: number }>;
};

/** Pure: kiterunner's `-o json` stdout to deduplicated discovered endpoints. */
export function parseKiterunnerOutput(stdout: string): KiterunnerEndpoint[] {
  const endpoints: KiterunnerEndpoint[] = [];
  const seen = new Set<string>();
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    let parsed: KiterunnerLine;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      continue;
    }
    const first = parsed.responses?.[0];
    if (!parsed.method || !parsed.path || !first || typeof first.sc !== "number") continue;
    const key = `${parsed.method}:${parsed.path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    endpoints.push({ method: parsed.method, path: parsed.path, statusCode: first.sc, contentLength: first.len ?? 0 });
  }
  return endpoints;
}

export async function runKiterunner(targetUrl: string): Promise<KiterunnerResult> {
  const wordlist = process.env.KITERUNNER_WORDLIST;
  if (!wordlist) return { status: "not_configured" };
  try {
    const { stdout } = await execTool(
      "kr",
      [
        "scan", targetUrl,
        "-w", wordlist,
        "-o", "json",
        "-q",
        "--fail-status-codes", "404,429",
        // Our wordlist is a flat list of route stems, not a grouped swagger
        // schema, so kiterunner's default two-phase gate (probe one route per
        // API group, full-scan only on a hit) finds nothing. Force the full
        // scan to probe every route.
        "--kitebuilder-full-scan",
        "--max-connection-per-host", "3",
        "--max-redirects", "2",
        "--timeout", "10s",
        // --wildcard-detection defaults on (a catch-all / SPA fallback that
        // answers every path the same is quarantined rather than reported as
        // hundreds of hits); it is a valueless flag, so leave it implicit.
      ],
      { timeout: KITERUNNER_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }
    );
    return { status: "completed", endpoints: parseKiterunnerOutput(stdout) };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") {
      return { status: "not_configured" };
    }
    return {
      status: "error",
      note: `kiterunner exited with error: ${error.message}`,
    };
  }
}

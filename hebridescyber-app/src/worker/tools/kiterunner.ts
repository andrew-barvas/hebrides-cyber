// Kiterunner integration — API endpoint brute-force discovery.
//
// Kiterunner uses contextual wordlists to discover API endpoints that
// aren't linked from the target's HTML or JavaScript. When the binary
// is absent, returns { status: "not_configured" } so the worker
// continues gracefully.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

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

function parseKiterunnerLine(line: string): KiterunnerEndpoint | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("[") || trimmed.startsWith("#")) return null;

  // Kiterunner output format: METHOD STATUS LENGTH PATH
  // e.g. "GET     200  1234  /api/v1/users"
  const match = trimmed.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\d{3})\s+(\d+)\s+(.+)$/);
  if (!match) return null;

  const [, method, status, length, path] = match;
  return {
    method: method!,
    path: path!.trim(),
    statusCode: parseInt(status!, 10),
    contentLength: parseInt(length!, 10),
  };
}

export async function runKiterunner(targetUrl: string): Promise<KiterunnerResult> {
  try {
    const { stdout } = await execFileAsync(
      "kr",
      [
        "scan", targetUrl,
        "-w", "routes-small.kite",
        "--fail-status-codes", "404,429",
        "-q",
        "-x", "5",
        "--max-redirects", "2",
      ],
      { timeout: KITERUNNER_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }
    );

    const endpoints: KiterunnerEndpoint[] = [];
    const seen = new Set<string>();

    for (const line of stdout.split("\n")) {
      const ep = parseKiterunnerLine(line);
      if (ep) {
        const key = `${ep.method}:${ep.path}`;
        if (!seen.has(key)) {
          seen.add(key);
          endpoints.push(ep);
        }
      }
    }

    return { status: "completed", endpoints };
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

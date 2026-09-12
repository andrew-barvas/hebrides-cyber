// Gospider integration — fast web crawling and JS endpoint discovery.
//
// Gospider crawls the target, follows links, and parses JavaScript files
// to find hidden API endpoints, subdomains, and AWS/S3/cloud resource
// references. When the binary is absent, returns
// { status: "not_configured" } so the worker continues gracefully.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const GOSPIDER_TIMEOUT_MS = 180_000;

export type GospiderEndpoint = {
  source: string;
  type: "url" | "js-endpoint" | "subdomain" | "aws-s3" | "form";
  value: string;
};

export type GospiderResult =
  | { status: "completed"; endpoints: GospiderEndpoint[] }
  | { status: "not_configured" }
  | { status: "error"; note: string };

function parseGospiderLine(line: string): GospiderEndpoint | null {
  const trimmed = line.trim();
  if (!trimmed) return null;

  // Gospider JSON output format: {"input":"...","source":"...","type":"...","output":"..."}
  try {
    const parsed = JSON.parse(trimmed) as {
      input?: string;
      source?: string;
      type?: string;
      output?: string;
    };
    if (!parsed.output) return null;

    let type: GospiderEndpoint["type"] = "url";
    const t = (parsed.type ?? "").toLowerCase();
    if (t.includes("javascript") || t.includes("js")) type = "js-endpoint";
    else if (t.includes("subdomain")) type = "subdomain";
    else if (t.includes("aws") || t.includes("s3")) type = "aws-s3";
    else if (t.includes("form")) type = "form";

    return {
      source: parsed.source ?? parsed.input ?? "",
      type,
      value: parsed.output,
    };
  } catch {
    // Non-JSON line — try plain text format: [type] - source - value
    const match = trimmed.match(/^\[([^\]]+)\]\s*-\s*(.+?)\s*-\s*(.+)$/);
    if (!match) return null;

    const [, rawType, source, value] = match;
    let type: GospiderEndpoint["type"] = "url";
    const t = (rawType ?? "").toLowerCase();
    if (t.includes("javascript") || t.includes("linkfinder")) type = "js-endpoint";
    else if (t.includes("subdomain")) type = "subdomain";
    else if (t.includes("aws") || t.includes("s3")) type = "aws-s3";
    else if (t.includes("form")) type = "form";

    return { source: source ?? "", type, value: value ?? "" };
  }
}

export async function runGospider(targetUrl: string): Promise<GospiderResult> {
  try {
    const { stdout } = await execFileAsync(
      "gospider",
      [
        "-s", targetUrl,
        "-c", "5",
        "-d", "2",
        "--json",
        "-t", "5",
        "--sitemap",
        "--robots",
        "-a",
      ],
      { timeout: GOSPIDER_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }
    );

    const endpoints: GospiderEndpoint[] = [];
    const seen = new Set<string>();

    for (const line of stdout.split("\n")) {
      const ep = parseGospiderLine(line);
      if (ep && !seen.has(ep.value)) {
        seen.add(ep.value);
        endpoints.push(ep);
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
      note: `gospider exited with error: ${error.message}`,
    };
  }
}

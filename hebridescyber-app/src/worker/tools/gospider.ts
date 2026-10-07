// Gospider integration: crawls the target and reads its JavaScript for the
// paths the site's own code calls (often API routes the HTML never links to)
// and for S3 bucket hosts. When the binary is absent, returns
// { status: "not_configured" } so the worker continues gracefully.
//
// Parsing follows real gospider v1.1.6 output (captured in
// fixtures/gospider/). Its --json lines are {input, source, type, output,
// status, length}, and the types mean:
//   url, robots, sitemap   a page on the site
//   form                   a page holding a form
//   javascript             a script file's URL (not an endpoint)
//   linkfinder             a path or URL found inside a script: relative
//                          paths and absolute URLs, third-party ones too
//   aws                    an S3 bucket host
//   subdomains             a subdomain of the target
// It also prints plain-text status lines ("[url] - [code-200] - …") among
// the JSON ones; those repeat JSON lines and are skipped.
//
// No -a (Archive.org, CommonCrawl, VirusTotal, AlienVault): it made a run
// hang for minutes, and historical URLs are waybackDiscovery.ts's job.

import { execTool } from "../../lib/execTool";

const execFileAsync = execTool;

const GOSPIDER_TIMEOUT_MS = 180_000;

export type GospiderEndpoint = {
  source: string;
  type: "url" | "js-file" | "js-endpoint" | "subdomain" | "aws-s3" | "form";
  value: string;
};

export type GospiderResult =
  | { status: "completed"; endpoints: GospiderEndpoint[] }
  | { status: "not_configured" }
  | { status: "error"; note: string };

const TYPES: Record<string, GospiderEndpoint["type"]> = {
  url: "url",
  robots: "url",
  sitemap: "url",
  form: "form",
  javascript: "js-file",
  linkfinder: "js-endpoint",
  aws: "aws-s3",
  subdomains: "subdomain",
};

/**
 * The site's own endpoint for a linkfinder hit, as an absolute URL on the
 * target's host, or null for a third-party URL or something that isn't a
 * path at all (linkfinder also matches strings like "text/html").
 */
function ownEndpoint(value: string, target: URL): string | null {
  if (value.startsWith("/") && !value.startsWith("//")) return new URL(value, target.origin).toString();
  try {
    const u = new URL(value);
    return (u.protocol === "http:" || u.protocol === "https:") && u.hostname === target.hostname ? u.toString() : null;
  } catch {
    return null;
  }
}

/** Pure: gospider's stdout to deduplicated endpoints. */
export function parseGospiderOutput(stdout: string, targetUrl: string): GospiderEndpoint[] {
  const target = new URL(targetUrl);
  const endpoints: GospiderEndpoint[] = [];
  const seen = new Set<string>();
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue; // plain-text status lines repeat JSON ones
    let parsed: { input?: string; source?: string; type?: string; output?: string };
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (!parsed.output) continue;
    const type = TYPES[(parsed.type ?? "").toLowerCase()] ?? "url";
    let value = parsed.output;
    if (type === "js-endpoint" || type === "url") {
      // A third-party library or CDN URL is not this site's endpoint, and
      // "url" entries are fetched by metadataLeak.ts, which must stay on the
      // scanned site.
      const own = ownEndpoint(value, target);
      if (!own) continue;
      value = own;
    }
    const key = `${type}|${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    endpoints.push({ source: parsed.source ?? parsed.input ?? "", type, value });
  }
  return endpoints;
}

export async function runGospider(targetUrl: string): Promise<GospiderResult> {
  try {
    const { stdout } = await execFileAsync(
      "gospider",
      ["-s", targetUrl, "-c", "5", "-d", "2", "--json", "-t", "1", "--timeout", "10", "--sitemap", "--robots"],
      { timeout: GOSPIDER_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }
    );
    return { status: "completed", endpoints: parseGospiderOutput(stdout, targetUrl) };
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

// HTTP host probing via httpx (ProjectDiscovery).
//
// Subdomain enumeration (subdomains.ts) lists hostnames; nothing then said
// which of them actually serve a live HTTP(S) application or what each one is.
// httpx fills that gap: one GET per host, reporting the live URL, status, page
// title, server banner, detected technologies and (over HTTPS) the certificate.
// That turns a flat subdomain list into a live attack-surface inventory — an
// admin panel or a forgotten staging app on a subdomain is exactly what this
// surfaces, and because each finding is keyed by host it rides findingsDiff.ts:
// a subdomain that starts serving a web app between scans shows up as NEW.
//
// SCOPE / POSTURE. One ordinary GET per host — read-only, no payloads, the same
// shape the base suite already sends to the target. It only ever probes the
// scanned target itself and hostnames already discovered within its own domain,
// never arbitrary hosts. No brute-forcing: the host list comes from passive
// enumeration, httpx is not asked to generate candidates.
//
// Targets are passed as `-u` arguments, never piped on stdin. httpx reads its
// target list from stdin by default, and execTool closes the child's stdin
// (without which a stdin-reading tool hangs until its timeout — the same bug
// that silently killed nuclei before execTool existed). Passing `-u` sidesteps
// stdin entirely.
//
// Parsing follows real httpx v1.6.10 `-json` output (fixture fixtures/httpx/):
// one JSON object per probed URL — {url, input, scheme, host, port, path,
// status_code, content_length, title?, webserver?, tech?[], failed, …}. A row
// with "failed": true never connected and is not a live host.

import { execTool } from "../execTool";
import type { Finding } from "./index";
import { LIVE_HOST_DISCOVERED } from "./remediationText";

const HTTPX_TIMEOUT_MS = 120_000;
// Hand httpx at most this many targets in one run — a busy domain can enumerate
// hundreds of subdomains, and this is an inventory pass, not an exhaustive one.
const MAX_PROBE_TARGETS = 100;
const HTTPX_MAX_BUFFER = 16 * 1024 * 1024;
// A domain with dozens of live subdomains must not produce dozens of rows:
// the first MAX_LIVE_FINDINGS get an individual info row, the rest a summary.
const MAX_LIVE_FINDINGS = 25;

export type HttpProbeRecord = {
  /** The target as supplied to httpx (lets a caller match back to its input). */
  input: string;
  /** The live URL httpx settled on (after any redirect httpx itself followed). */
  url: string;
  host: string;
  port: string;
  scheme: string;
  statusCode: number;
  contentLength: number;
  /** Page <title>, when httpx captured one. */
  title: string | null;
  /** Server banner, when present. */
  webserver: string | null;
  /** Technologies httpx fingerprinted, e.g. ["Python:3.11.15"]. */
  tech: string[];
};

export type HttpProbeResult =
  | { status: "completed"; results: HttpProbeRecord[] }
  | { status: "not_configured"; results: [] }
  | { status: "error"; results: []; note: string };

type HttpxLine = {
  input?: string;
  url?: string;
  host?: string;
  port?: string;
  scheme?: string;
  status_code?: number;
  content_length?: number;
  title?: string;
  webserver?: string;
  tech?: string[];
  failed?: boolean;
};

/** Pure: httpx's `-json` stdout to deduplicated live-host records. */
export function parseHttpxOutput(stdout: string): HttpProbeRecord[] {
  const records: HttpProbeRecord[] = [];
  const seen = new Set<string>();
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    let parsed: HttpxLine;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      continue;
    }
    // A failed probe never connected — it is not a live host, so it is not
    // evidence of anything and is dropped (never reported as "down").
    if (parsed.failed === true) continue;
    if (!parsed.url || typeof parsed.status_code !== "number") continue;
    if (seen.has(parsed.url)) continue;
    seen.add(parsed.url);
    records.push({
      input: parsed.input ?? parsed.url,
      url: parsed.url,
      host: parsed.host ?? "",
      port: parsed.port ?? "",
      scheme: parsed.scheme ?? "",
      statusCode: parsed.status_code,
      contentLength: typeof parsed.content_length === "number" ? parsed.content_length : 0,
      title: parsed.title?.trim() || null,
      webserver: parsed.webserver?.trim() || null,
      tech: Array.isArray(parsed.tech) ? parsed.tech.filter((t) => typeof t === "string") : [],
    });
  }
  return records;
}

/**
 * Probe the target and a bounded set of already-discovered hosts. `extraHosts`
 * are hostnames or URLs from subdomain enumeration; bare hostnames are probed
 * as-is (httpx tries https then http). The primary target is always probed
 * first and is never dropped by the cap.
 */
export async function runHttpProbe(targetUrl: string, extraHosts: string[] = []): Promise<HttpProbeResult> {
  let primary: string;
  try {
    primary = new URL(targetUrl).toString();
  } catch {
    return { status: "error", results: [], note: "Invalid URL" };
  }

  const targets: string[] = [];
  const seen = new Set<string>();
  for (const candidate of [primary, ...extraHosts]) {
    const value = candidate.trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    targets.push(value);
    if (targets.length >= MAX_PROBE_TARGETS) break;
  }

  try {
    const { stdout } = await execTool(
      "httpx",
      [
        "-u", targets.join(","),
        "-json",
        "-silent",
        "-no-color",
        "-timeout", "10",
        "-status-code",
        "-title",
        "-tech-detect",
        "-tls-grab",
      ],
      { timeout: HTTPX_TIMEOUT_MS, maxBuffer: HTTPX_MAX_BUFFER }
    );
    return { status: "completed", results: parseHttpxOutput(stdout) };
  } catch (err) {
    const error = err as NodeJS.ErrnoException & { stdout?: string };
    // Binary absent — the "running outside the CI worker" case, same contract
    // as the other extended tools: report it, never throw.
    if (error.code === "ENOENT") return { status: "not_configured", results: [] };
    // httpx can exit non-zero yet have already printed the hosts it reached;
    // keep those rather than discarding the whole run.
    if (typeof error.stdout === "string" && error.stdout.trim().length > 0) {
      return { status: "completed", results: parseHttpxOutput(error.stdout) };
    }
    return { status: "error", results: [], note: `httpx exited with error: ${error.message}` };
  }
}

/**
 * Inventory findings for the discovered hosts that serve a live app. The
 * scanned target itself is excluded — the base suite (fingerprint, headers,
 * TLS) already covers it, so the net-new signal here is the *other* hostnames
 * that turned out to be live. Keyed by host so findingsDiff.ts flags a
 * subdomain that starts serving a web app as NEW; sorted + capped so the cap
 * doesn't flap arbitrary hosts between NEW and FIXED between scans.
 */
export function buildHttpProbeFindings(targetUrl: string, results: HttpProbeRecord[]): Finding[] {
  let primaryHost = "";
  try {
    primaryHost = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    /* targetUrl already validated upstream; an unparseable one just means no host is excluded */
  }

  const seen = new Set<string>();
  const others = results
    .filter((r) => {
      const host = r.host.toLowerCase();
      if (!host || host === primaryHost) return false;
      if (seen.has(host)) return false;
      seen.add(host);
      return true;
    })
    .sort((a, b) => a.url.localeCompare(b.url));

  const findings: Finding[] = [];
  const listed = others.slice(0, MAX_LIVE_FINDINGS);
  for (const r of listed) {
    const bits = [`[${r.statusCode}]`];
    if (r.title) bits.push(`"${r.title}"`);
    if (r.tech.length > 0) bits.push(`tech: ${r.tech.join(", ")}`);
    if (r.webserver) bits.push(`server: ${r.webserver}`);
    findings.push({
      checkId: `http-probe.live:${r.host}`,
      severity: "info",
      title: `Live host: ${r.url}`,
      detail: `${r.url} is serving a live HTTP response (${bits.join("; ")}). Discovered by probing enumerated hostnames (httpx); asset inventory only — no vulnerability is implied.`,
      remediation: LIVE_HOST_DISCOVERED,
    });
  }

  const remaining = others.length - listed.length;
  if (remaining > 0) {
    findings.push({
      checkId: "http-probe.live-additional",
      severity: "info",
      title: `${remaining} further live host(s) not listed individually`,
      detail: `httpx found ${others.length} live hosts beyond the scanned site; the first ${MAX_LIVE_FINDINGS} are listed above. Additional: ${others.slice(MAX_LIVE_FINDINGS, MAX_LIVE_FINDINGS + 10).map((r) => r.host).join(", ")}${remaining > 10 ? ` (+${remaining - 10} more)` : ""}.`,
      remediation: LIVE_HOST_DISCOVERED,
    });
  }

  return findings;
}

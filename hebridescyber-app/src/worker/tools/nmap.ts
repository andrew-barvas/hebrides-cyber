// nmap port scanner integration.
//
// Uses the nmap binary — available in the worker Docker container. Falls back
// to "not_configured" gracefully in environments where nmap is absent (Azure
// Functions, local dev without Docker). SSRF validation is done upstream by
// run-scan before the job is enqueued — the worker trusts targetUrl.
//
// Runs service/version detection (-sV) on a fixed list of known-dangerous
// ports — databases, Docker, Elasticsearch, etcd, Consul, remote shells.
// Broad open-port discovery is ports.ts's job (Shodan InternetDB, passive).
// This used to also pass --top-ports 1000, but with -p present nmap takes
// the top ports *from within* the -p list, so it never added anything; the
// header claimed a top-1000 scan that wasn't happening. It is also a TCP
// connect scan, not SYN: the runner doesn't run nmap as root.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const NMAP_TIMEOUT_MS = 120_000;

export type NmapPort = {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string | null;
};

export type NmapResult =
  | { status: "completed"; host: string; ports: NmapPort[]; osGuess: string | null }
  | { status: "not_configured"; host: string; ports: [] }
  | { status: "error"; host: string; ports: []; note: string };

const DANGEROUS_PORTS = [21, 22, 23, 25, 3306, 5432, 6379, 27017, 9200, 2375, 2376, 8500, 2379];

function xmlAttr(tag: string, name: string): string | null {
  const m = tag.match(new RegExp(`\\b${name}="([^"]*)"`));
  if (!m) return null;
  return m[1].replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

/**
 * Open ports from nmap's -oX output, one <port> element at a time. The old
 * single regex ran across element boundaries: a port whose <service> had no
 * version attribute borrowed the *next* port's service and version, and
 * that next port vanished from the results.
 */
export function parseNmapXml(xml: string): NmapPort[] {
  const ports: NmapPort[] = [];
  for (const block of xml.matchAll(/<port\b([^>]*)>([\s\S]*?)<\/port>/g)) {
    const [, attrs, body] = block;
    const state = xmlAttr(body.match(/<state\b[^>]*>/)?.[0] ?? "", "state");
    if (state !== "open") continue;
    const port = Number(xmlAttr(attrs, "portid"));
    if (!Number.isInteger(port)) continue;
    const service = body.match(/<service\b[^>]*>/)?.[0] ?? "";
    // nmap splits "OpenSSH 8.9p1" into product="OpenSSH" version="8.9p1".
    const version = [xmlAttr(service, "product"), xmlAttr(service, "version")].filter(Boolean).join(" ");
    ports.push({
      port,
      protocol: xmlAttr(attrs, "protocol") ?? "tcp",
      state,
      service: xmlAttr(service, "name") || "unknown",
      version: version || null,
    });
  }
  return ports;
}

export async function runNmap(targetUrl: string): Promise<NmapResult> {
  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    return { status: "error", host: targetUrl, ports: [], note: "Invalid URL" };
  }

  try {
    const { stdout } = await execFileAsync(
      "nmap",
      [
        "-sV",                // service/version detection
        "--open",             // only open ports
        "-p", DANGEROUS_PORTS.join(","),
        "-oX", "-",           // XML output to stdout
        hostname,
      ],
      { timeout: NMAP_TIMEOUT_MS }
    );

    const ports = parseNmapXml(stdout);

    // Only present if OS detection (-O, root only) ever runs; null today.
    const osMatch = /<osclass[^>]+osfamily="([^"]+)"/.exec(stdout);
    const osGuess = osMatch ? osMatch[1] : null;

    return { status: "completed", host: hostname, ports, osGuess };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") {
      return { status: "not_configured", host: hostname, ports: [] };
    }
    return {
      status: "error",
      host: hostname,
      ports: [],
      note: `nmap exited: ${error.message}`,
    };
  }
}

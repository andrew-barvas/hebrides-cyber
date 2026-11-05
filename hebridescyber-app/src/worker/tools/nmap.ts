// nmap port scanner integration.
//
// Uses the nmap binary — available in the worker Docker container. Falls back
// to "not_configured" gracefully in environments where nmap is absent (Azure
// Functions, local dev without Docker). SSRF validation is done upstream by
// run-scan before the job is enqueued — the worker trusts targetUrl.
//
// Runs service/version detection (-sV) on a fixed list of known-dangerous
// ports — databases, Docker, Elasticsearch, etcd, Consul, remote shells.
// Broad open-port discovery is ports.ts's job (direct TCP connect, no nmap).
// This used to also pass --top-ports 1000, but with -p present nmap takes
// the top ports *from within* the -p list, so it never added anything; the
// header claimed a top-1000 scan that wasn't happening. It is also a TCP
// connect scan, not SYN: the runner doesn't run nmap as root.

import { execTool } from "../../lib/execTool";

const execFileAsync = execTool;

const NMAP_TIMEOUT_MS = 120_000;

export type NmapPort = {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string | null;
  /** nmap's product attribute alone ("OpenSSH"). Absent on hand-built ports. */
  product?: string | null;
  /** nmap's version attribute alone ("8.9p1 Ubuntu 3ubuntu0.10"). */
  productVersion?: string | null;
  /** nmap's extrainfo attribute ("Ubuntu Linux; protocol 2.0"). */
  extraInfo?: string | null;
  /**
   * The <cpe> elements nmap emitted for this service, as written (CPE 2.2
   * URIs such as "cpe:/a:openbsd:openssh:8.9p1"). Empty when nmap matched no
   * CPE; serviceCve.ts matches CVEs from these.
   */
  cpes?: string[];
};

export type NmapResult =
  | { status: "completed"; host: string; ports: NmapPort[]; osGuess: string | null }
  | { status: "not_configured"; host: string; ports: [] }
  | { status: "error"; host: string; ports: []; note: string };

const DANGEROUS_PORTS = [21, 22, 23, 25, 3306, 5432, 6379, 27017, 9200, 2375, 2376, 8500, 2379];

function unescapeXml(s: string): string {
  return s.replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

function xmlAttr(tag: string, name: string): string | null {
  const m = tag.match(new RegExp(`\\b${name}="([^"]*)"`));
  if (!m) return null;
  return unescapeXml(m[1]);
}

/**
 * The <cpe> children of one port's <service> element. nmap writes the
 * service as `<service .../>` when it has no CPE and as
 * `<service ...><cpe>…</cpe></service>` when it has one or more.
 */
function serviceCpes(body: string): string[] {
  const service = body.match(/<service\b[^>]*?(?:\/>|>([\s\S]*?)<\/service>)/);
  const inner = service?.[1] ?? "";
  return [...inner.matchAll(/<cpe>([^<]*)<\/cpe>/g)].map((m) => unescapeXml(m[1]).trim()).filter(Boolean);
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
    const product = xmlAttr(service, "product") || null;
    const productVersion = xmlAttr(service, "version") || null;
    const version = [product, productVersion].filter(Boolean).join(" ");
    ports.push({
      port,
      protocol: xmlAttr(attrs, "protocol") ?? "tcp",
      state,
      service: xmlAttr(service, "name") || "unknown",
      version: version || null,
      product,
      productVersion,
      extraInfo: xmlAttr(service, "extrainfo") || null,
      cpes: serviceCpes(body),
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

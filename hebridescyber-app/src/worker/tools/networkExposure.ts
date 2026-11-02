// Network exposure scanning: broad port discovery (naabu top-1000) feeding
// service/version detection (nmap -sV) on whatever's actually open.
//
// ports.ts (base suite) TCP-connects to 30 fixed ports; nmap.ts (extended)
// runs -sV on a fixed dangerous-ports list. Neither does broad discovery — a
// risky service on an unusual port (a database on 3307, a dev server on 5000)
// is invisible to both. naabu's top-1000 sweep finds what's open; nmap then
// identifies the service on exactly those ports.
//
// Shells out via execTool (never bare execFile — see execTool.ts). Both binaries
// are installed only in the scheduled-scans workflow; absent → not_configured.
// Evidence discipline (docs/SCANNER-CONVENTIONS.md): a failed or absent binary
// is "not_configured"/"error", NEVER an empty "clean" — findingLifecycle.ts
// would otherwise mark last scan's open ports fixed and close their tickets.
//
// Port risk reuses ports.ts's PORT_TARGETS classification where a discovered
// port is one of the 30 it knows; anything else is "info" with a generic note.
//
// Each identified service is then matched against known CVEs and end-of-life
// dates by serviceCve.ts, from the banner nmap already read (no extra traffic
// to the target). `incompleteChecks` lists the checkId prefixes that matching
// could not evaluate, so findingLifecycle.ts leaves those findings as they were.
import { execTool } from "../../lib/execTool";
import { parseNmapXml, type NmapPort } from "./nmap";
import { PORT_RISK, type PortRisk } from "../../lib/scanners/portRisk";
import type { CveIndex } from "../../lib/cveIndex";
import { matchServiceCves, incompleteServiceChecks, SERVICE_EOL_CHECK, SERVICE_VERSION_UNKNOWN_CHECK, type ServiceCveOptions, type ServiceCveResult } from "./serviceCve";

const NAABU_TIMEOUT_MS = 180_000;
const NMAP_TIMEOUT_MS = 120_000;

export type NetworkExposurePort = {
  port: number;
  protocol: string;
  service: string;
  version: string | null;
  risk: PortRisk["risk"];
  reason: string;
  /** nmap's <cpe> elements for the service (CPE 2.2 URIs); empty when none. */
  cpes: string[];
};

export type NetworkExposureResult =
  | {
      status: "completed";
      host: string;
      ports: NetworkExposurePort[];
      /** Known-CVE and end-of-life matching for the identified services. */
      serviceCves: ServiceCveResult;
      /** checkId prefixes this run could not evaluate (see findingLifecycle.ts). */
      incompleteChecks: string[];
    }
  | { status: "not_configured"; host: string; ports: [] }
  | { status: "error"; host: string; ports: []; note: string };

/**
 * Open ports from naabu's `-json` output: one JSON object per line, each with
 * a numeric `port`. Pure — tested against captured output. Anything that isn't
 * a line with an integer port is ignored (naabu also prints banners/progress
 * to stderr, which never reaches here).
 */
export function parseNaabuJson(raw: string): number[] {
  const ports = new Set<number>();
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    try {
      const obj = JSON.parse(trimmed) as { port?: unknown };
      const port = Number(obj.port);
      if (Number.isInteger(port) && port > 0 && port <= 65535) ports.add(port);
    } catch {
      // not a JSON line — skip
    }
  }
  return [...ports].sort((a, b) => a - b);
}

/** Classifies a discovered port, reusing ports.ts's risk table where it knows one. */
export function classifyPort(port: NmapPort): NetworkExposurePort {
  const known = PORT_RISK[port.port];
  return {
    port: port.port,
    protocol: port.protocol,
    service: port.service !== "unknown" ? port.service : known?.service ?? "unknown",
    version: port.version,
    cpes: port.cpes ?? [],
    risk: known?.risk ?? "info",
    reason:
      known?.reason ??
      `Port ${port.port} (${port.service}) is reachable from the internet. Confirm this service is meant to be publicly exposed and is restricted to the clients that need it.`,
  };
}

export type NetworkExposureOptions = ServiceCveOptions & {
  /** The CPE -> CVE index to match services against; absent → matching is not_configured. */
  cveIndex?: CveIndex | null;
};

export async function runNetworkExposure(targetUrl: string, options: NetworkExposureOptions = {}): Promise<NetworkExposureResult> {
  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    return { status: "error", host: targetUrl, ports: [], note: "Invalid URL" };
  }

  // 1. naabu top-1000 discovery.
  let openPorts: number[];
  try {
    const { stdout } = await execTool(
      "naabu",
      ["-host", hostname, "-top-ports", "1000", "-silent", "-json", "-no-color"],
      { timeout: NAABU_TIMEOUT_MS }
    );
    openPorts = parseNaabuJson(stdout);
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") return { status: "not_configured", host: hostname, ports: [] };
    return { status: "error", host: hostname, ports: [], note: `naabu exited: ${error.message}` };
  }

  // Nothing open is a genuine, evidenced result — not an error.
  if (openPorts.length === 0) {
    return { status: "completed", host: hostname, ports: [], serviceCves: { status: "checked", services: [], indexedThrough: null }, incompleteChecks: [] };
  }

  // 2. nmap -sV service/version detection on exactly the discovered ports.
  // nmap being absent while naabu succeeded is still a partial answer: report
  // the open ports without version detail rather than discarding real evidence.
  let nmapPorts: NmapPort[] = [];
  let nmapFailed = false;
  try {
    const { stdout } = await execTool(
      "nmap",
      ["-sV", "--open", "-p", openPorts.join(","), "-oX", "-", hostname],
      { timeout: NMAP_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }
    );
    nmapPorts = parseNmapXml(stdout);
  } catch {
    // nmap missing or failed — fall back to the discovered ports with no service.
    nmapFailed = true;
    nmapPorts = openPorts.map((port) => ({ port, protocol: "tcp", state: "open", service: "unknown", version: null }));
  }

  // naabu found a port but nmap reported it closed on its own connect → trust
  // naabu (the port answered), carry it through with no service detail.
  const byPort = new Map(nmapPorts.map((p) => [p.port, p]));
  for (const port of openPorts) {
    if (!byPort.has(port)) byPort.set(port, { port, protocol: "tcp", state: "open", service: "unknown", version: null });
  }

  const identified = [...byPort.values()].sort((a, b) => a.port - b.port);
  const ports = identified.map(classifyPort);

  // Without service detection there is nothing to match: say so rather than
  // reporting every service clean.
  const serviceCves: ServiceCveResult = nmapFailed
    ? { status: "error", note: "nmap service detection failed; no service could be matched against known CVEs.", services: [] }
    : await matchServiceCves(identified, options.cveIndex ?? null, options);
  const incompleteChecks = incompleteServiceChecks(serviceCves);
  // No banners at all: every service check is unevaluated, not just the CVE one.
  if (nmapFailed) incompleteChecks.push(SERVICE_EOL_CHECK, SERVICE_VERSION_UNKNOWN_CHECK);
  return { status: "completed", host: hostname, ports, serviceCves, incompleteChecks };
}

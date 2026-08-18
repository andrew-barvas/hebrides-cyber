// nmap port scanner integration.
//
// Uses the nmap binary — available in the worker Docker container. Falls back
// to "not_configured" gracefully in environments where nmap is absent (Azure
// Functions, local dev without Docker). SSRF validation is done upstream by
// run-scan before the job is enqueued — the worker trusts targetUrl.
//
// Runs a SYN scan with OS/service detection on the top 1000 ports, then
// augments with targeted checks on known dangerous ports.

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
        "--top-ports", "1000",
        "-p", DANGEROUS_PORTS.join(","),
        "-oX", "-",           // XML output to stdout
        hostname,
      ],
      { timeout: NMAP_TIMEOUT_MS }
    );

    const ports: NmapPort[] = [];
    // Regex uses s flag (dotall) — TypeScript targets es2018+ so this is safe in Node 18+.
    const portPattern = new RegExp('<port protocol="(\\w+)" portid="(\\d+)">.*?<state state="(\\w+)".*?<service name="([^"]*)"(?:[^/]*)version="([^"]*)".*?<\\/port>', "gs");

    let match: RegExpExecArray | null;
    while ((match = portPattern.exec(stdout)) !== null) {
      if (match[3] === "open") {
        ports.push({
          protocol: match[1],
          port: parseInt(match[2], 10),
          state: match[3],
          service: match[4] ?? "unknown",
          version: match[5] ? match[5] : null,
        });
      }
    }

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

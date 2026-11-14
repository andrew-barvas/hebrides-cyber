// Helper tools networkExposure.ts runs around its naabu + nmap core
// (LOOKOUT-TOOL-SHORTLIST.md ranks 2 to 5). Each is a pinned binary installed
// by docker/scan-tools.sh, shelled out through execTool, and each reports
// "not_configured" when absent and "error" when it fails, never an empty clean.
//
//   cdncheck   Is the hostname a CDN or WAF edge (Cloudflare, Akamai...)? If so
//              networkExposure doesn't port-scan it: those ports belong to the
//              provider, not the customer, and scanning them says nothing
//              about the customer's own servers.
//   ssh-audit  One unauthenticated SSH handshake per SSH port: weak key
//              exchange, host key, cipher and MAC algorithms, and CVEs for the
//              server version.
//   tlsx       Certificates on open TLS ports other than 443 (deepTls covers
//              443): expired, self-signed, wrong hostname or untrusted.
//   dnsx       One zone-transfer (AXFR) request per name server of the
//              registrable domain. A server that answers hands out every
//              record in the zone.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execTool } from "../../lib/execTool";
import type { Finding } from "../../lib/scanners";

const CDNCHECK_TIMEOUT_MS = 30_000;
const SSH_AUDIT_TIMEOUT_MS = 60_000;
const TLSX_TIMEOUT_MS = 60_000;
const DNSX_TIMEOUT_MS = 60_000;

export type ToolOutcome<T> = { status: "checked"; value: T } | { status: "not_configured" } | { status: "error"; note: string };

/** execTool rejects on a non-zero exit; ssh-audit exits non-zero exactly when it found problems. */
async function run(cmd: string, args: string[], timeout: number, okExitCodes: number[] = [0]): Promise<ToolOutcome<string>> {
  try {
    const { stdout } = await execTool(cmd, args, { timeout, maxBuffer: 10 * 1024 * 1024 });
    return { status: "checked", value: stdout };
  } catch (err) {
    const e = err as NodeJS.ErrnoException & { code?: string | number; stdout?: string; killed?: boolean };
    if (e.code === "ENOENT") return { status: "not_configured" };
    if (typeof e.code === "number" && okExitCodes.includes(e.code) && typeof e.stdout === "string") return { status: "checked", value: e.stdout };
    return { status: "error", note: `${cmd} failed: ${e.killed ? "timed out" : e.message}` };
  }
}

function jsonLines(raw: string): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    try {
      out.push(JSON.parse(t) as Record<string, unknown>);
    } catch {
      // progress or banner text
    }
  }
  return out;
}

// ---- cdncheck -----------------------------------------------------------------

/** The CDN or WAF provider in front of the host, or null when cdncheck saw none. */
export function parseCdncheck(raw: string): string | null {
  for (const r of jsonLines(raw)) {
    if (r.cdn === true || r.waf === true) return String(r.cdn_name || r.waf_name || "a CDN or WAF");
  }
  return null;
}

export async function edgeProvider(host: string): Promise<ToolOutcome<string | null>> {
  const res = await run("cdncheck", ["-i", host, "-j", "-silent", "-nc", "-duc"], CDNCHECK_TIMEOUT_MS);
  return res.status === "checked" ? { status: "checked", value: parseCdncheck(res.value) } : res;
}

// ---- ssh-audit ----------------------------------------------------------------

export const SSH_ALGORITHM_CHECK = "network-exposure.ssh-weak-algorithm";
export const SSH_CVE_CHECK = "network-exposure.ssh-cve";

type SshAlgo = { algorithm?: string; name?: string; notes?: { fail?: string[]; warn?: string[] } };
type SshAuditJson = {
  banner?: { software?: string | null };
  cves?: Array<{ name?: string; cvssv2?: number; description?: string }>;
  kex?: SshAlgo[];
  key?: SshAlgo[];
  enc?: SshAlgo[];
  mac?: SshAlgo[];
};

const SSH_KINDS: Array<[keyof SshAuditJson, string]> = [
  ["kex", "key exchange"],
  ["key", "host key"],
  ["enc", "cipher"],
  ["mac", "MAC"],
];

export function sshAuditFindings(host: string, port: number, report: SshAuditJson, remediation: string): Finding[] {
  const findings: Finding[] = [];
  const failing: string[] = [];
  for (const [kind, label] of SSH_KINDS) {
    for (const a of (report[kind] as SshAlgo[] | undefined) ?? []) {
      const name = a.algorithm ?? a.name;
      if (name && (a.notes?.fail?.length ?? 0) > 0) failing.push(`${label} ${name} (${a.notes!.fail![0]})`);
    }
  }
  if (failing.length > 0) {
    findings.push({
      checkId: `${SSH_ALGORITHM_CHECK}:${port}`,
      severity: "medium",
      title: `[network] SSH on port ${port} offers weak algorithms`,
      detail: `ssh-audit's handshake with ${host}:${port} found ${failing.length} algorithm${failing.length === 1 ? "" : "s"} it rates as failing: ${failing.slice(0, 8).join("; ")}${failing.length > 8 ? "; and more" : ""}.`,
      remediation,
    });
  }
  for (const cve of report.cves ?? []) {
    if (!cve.name || !/^CVE-\d{4}-\d{4,}$/.test(cve.name)) continue;
    const score = typeof cve.cvssv2 === "number" ? cve.cvssv2 : null;
    findings.push({
      checkId: `${SSH_CVE_CHECK}:${port}:${cve.name}`,
      severity: score === null ? "medium" : score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low",
      title: `[network] ${cve.name} in the SSH server on port ${port}`,
      detail: `ssh-audit matched the server version ${report.banner?.software ?? "it identified"} to ${cve.name}${score !== null ? ` (CVSS v2 ${score})` : ""}: ${cve.description ?? "see the CVE record"}. Version matching can be wrong when a distribution backports fixes, so check the installed package's changelog.`,
      cveIds: [cve.name],
      remediation,
    });
  }
  return findings;
}

export async function runSshAudit(host: string, port: number, remediation: string): Promise<ToolOutcome<Finding[]>> {
  // Exit codes: 0 good, 1 warnings, 2 failures, 3 unknown. 1 to 3 still print the JSON report.
  const res = await run("ssh-audit", ["-j", "-p", String(port), host], SSH_AUDIT_TIMEOUT_MS, [1, 2, 3]);
  if (res.status !== "checked") return res;
  try {
    return { status: "checked", value: sshAuditFindings(host, port, JSON.parse(res.value) as SshAuditJson, remediation) };
  } catch {
    return { status: "error", note: `ssh-audit gave no JSON report for port ${port}` };
  }
}

// ---- tlsx ---------------------------------------------------------------------

export const TLS_CERT_CHECK = "network-exposure.tls-cert";

export function tlsxFindings(host: string, raw: string, remediation: string): { findings: Finding[]; probed: number[] } {
  const findings: Finding[] = [];
  const probed: number[] = [];
  for (const r of jsonLines(raw)) {
    const port = Number(r.port);
    if (!Number.isInteger(port)) continue;
    if (r.probe_status !== true) continue; // no handshake: nothing evidenced either way
    probed.push(port);
    const problems: string[] = [];
    if (r.expired === true) problems.push(`it expired on ${String(r.not_after ?? "an earlier date").slice(0, 10)}`);
    if (r.self_signed === true) problems.push("it is self-signed");
    if (r.mismatched === true) problems.push(`it doesn't cover ${host}`);
    if (r.untrusted === true && r.self_signed !== true) problems.push("it doesn't chain to a trusted certificate authority");
    if (r.revoked === true) problems.push("it has been revoked");
    if (problems.length === 0) continue;
    findings.push({
      checkId: `${TLS_CERT_CHECK}:${port}`,
      severity: r.expired === true || r.revoked === true ? "high" : "medium",
      title: `[network] Certificate problem on port ${port}`,
      detail: `The TLS certificate served on ${host}:${port}${r.subject_cn ? ` (for ${String(r.subject_cn)})` : ""} has a problem: ${problems.join(", ")}. Clients either show a warning or, if they skip the check, can be intercepted.`,
      remediation,
    });
  }
  return { findings, probed };
}

export async function runTlsx(host: string, ports: number[], remediation: string): Promise<ToolOutcome<Finding[]>> {
  if (ports.length === 0) return { status: "checked", value: [] };
  const res = await run("tlsx", ["-u", host, "-p", ports.join(","), "-j", "-silent", "-nc", "-ex", "-ss", "-mm", "-un", "-re", "-cn", "-duc"], TLSX_TIMEOUT_MS);
  if (res.status !== "checked") return res;
  const { findings, probed } = tlsxFindings(host, res.value, remediation);
  // A port tlsx couldn't handshake with wasn't evaluated, so the whole check isn't clean.
  if (probed.length < ports.length) return { status: "error", note: `tlsx couldn't complete a handshake on ${ports.filter((p) => !probed.includes(p)).join(", ")}` };
  return { status: "checked", value: findings };
}

// ---- dnsx (zone transfer) -------------------------------------------------------

export const ZONE_TRANSFER_CHECK = "network-exposure.zone-transfer";

export function zoneTransferFinding(domain: string, raw: string, remediation: string): Finding | null {
  for (const r of jsonLines(raw)) {
    const axfr = r.axfr as { chain?: Array<{ all?: string[]; resolver?: string[] }> } | undefined;
    const chain = (axfr?.chain ?? []).filter((c) => (c.all?.length ?? 0) > 0);
    if (chain.length === 0) continue;
    const servers = [...new Set(chain.flatMap((c) => c.resolver ?? []))];
    const records = chain.reduce((n, c) => n + (c.all?.length ?? 0), 0);
    return {
      checkId: `${ZONE_TRANSFER_CHECK}:${domain}`,
      severity: "high",
      title: `[network] DNS zone transfer allowed for ${domain}`,
      detail: `${servers.length > 0 ? servers.join(", ") : "A name server"} answered a zone-transfer (AXFR) request for ${domain} with ${records} record${records === 1 ? "" : "s"}, so anyone can list every host name in the zone, including ones never meant to be public.`,
      remediation,
    };
  }
  return null;
}

export async function runZoneTransferCheck(domain: string, remediation: string): Promise<ToolOutcome<Finding[]>> {
  // -d is dnsx's brute-force input, and execTool closes stdin, so the domain goes in a one-line list file.
  const dir = mkdtempSync(join(tmpdir(), "dnsx-"));
  const list = join(dir, "domains.txt");
  writeFileSync(list, `${domain}\n`);
  let res: ToolOutcome<string>;
  try {
    res = await run("dnsx", ["-l", list, "-axfr", "-j", "-silent", "-nc", "-duc", "-or"], DNSX_TIMEOUT_MS);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  if (res.status !== "checked") return res;
  const finding = zoneTransferFinding(domain, res.value, remediation);
  return { status: "checked", value: finding ? [finding] : [] };
}

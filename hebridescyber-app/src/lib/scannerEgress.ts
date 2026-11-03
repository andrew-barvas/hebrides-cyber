// The source IP our scans come from, published so customers can allowlist it
// in a WAF or tell their security team who is knocking.
//
// Empty until the owner applies azure/terraform/scan-workers.tf, which
// allocates the static IP behind the scan workers' NAT gateway (the
// `scan_egress_ip` output). Then put that address here, once, in a reviewed
// change: an IP customers allowlist must never change by accident, so it is a
// constant, not an environment setting. Until then /trust says the address is
// not published yet, and never shows a made-up one.
//
// Scans from the GitHub Actions fallback (scheduled-scans.yml,
// on-demand-scan.yml) leave from GitHub's shared runner ranges instead; the
// /trust copy says so.
import { isIP } from "node:net";

export const SCANNER_EGRESS_IPS: readonly string[] = [];

/** The published addresses, dropping anything that isn't a literal IPv4/IPv6 address. */
export function publishedScannerIps(ips: readonly string[] = SCANNER_EGRESS_IPS): string[] {
  return ips.map((ip) => ip.trim()).filter((ip) => isIP(ip) !== 0);
}

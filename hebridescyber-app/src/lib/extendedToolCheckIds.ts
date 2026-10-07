// Single source of truth for "can this finding be re-verified by an
// on-demand scan?" — imported by both src/pages/api/scans/[id]/retest-finding.ts
// (server-side rejection) and src/components/ScanReportView.tsx (hides the
// retest button proactively) so the two never drift apart.
//
// The on-demand scan path (any "Scan now" click, including a retest) always
// resolves to the "safe" scan profile — see src/scripts/run-queued-scan-jobs.ts's
// resolveScanConfig() and src/lib/scanProfiles.ts — which runs none of the
// extended tools listed below. A finding whose checkId module prefix
// belongs to one of these tools can therefore never be genuinely
// re-verified by an on-demand rescan: retesting it anyway would silently
// report "fixed" just because the tool that found it never ran again.
// Getting this list wrong in either direction is a real correctness bug,
// not just a missing feature — see docs/ENHANCEMENTS.md E-30. Keep this in
// sync with src/lib/scanProfiles.ts's EXTENDED_TOOL_NAMES (that list is the
// TS identifier per tool; this one is each tool's checkId prefix).
export const EXTENDED_TOOL_PREFIXES = [
  "nuclei",
  "zap",
  "sqlmap",
  "xsser", // retired tool: kept so a finding it once stored is never treated as re-verifiable by an on-demand rescan
  "commix",
  "nmap",
  "subdomains",
  "deep-tls",
  "secretScan",
  "dependency-manifest",
  "docker-base-image",
  "trivy-image",
  "trivy-config",
  "sast",
  "auth-check",
  "whatwaf",
  "wpscan",
  "cmsmap",
  "photon",
  "gospider",
  "zapAjaxSpider",
  "metadataLeak",
  "kiterunner",
  "arjun",
  "sessionCheck",
  "cloudPosture",
  "http-probe",
  "content-discovery",
  "credential-spray",
  "strix",
  "cairn",
] as const;

export function isExtendedToolFinding(checkId: string | undefined): boolean {
  if (!checkId) return false;
  // The signed-in crawl (crawl.auth.*) only runs in the extended suite; the anonymous crawl.* does not.
  if (checkId.startsWith("crawl.auth.")) return true;
  return (EXTENDED_TOOL_PREFIXES as readonly string[]).includes(checkId.split(".")[0]);
}

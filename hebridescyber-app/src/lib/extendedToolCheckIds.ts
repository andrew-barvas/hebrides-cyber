// Single source of truth for "can this finding be re-verified by an
// on-demand scan?" — imported by both src/pages/api/scans/[id]/retest-finding.ts
// (server-side rejection) and src/components/ScanReportView.tsx (hides the
// retest button proactively) so the two never drift apart.
//
// The on-demand scan path (any "Scan now" click, including a retest) never
// runs the 12 extended tools — see src/scripts/run-queued-scan-jobs.ts:
// `const runExtendedTools = !scanId` — only a scheduled job (no scan_id
// preset) does. A finding whose checkId module prefix belongs to one of
// these tools can therefore never be genuinely re-verified by an on-demand
// rescan: retesting it anyway would silently report "fixed" just because
// the tool that found it never ran again. Getting this list wrong in either
// direction is a real correctness bug, not just a missing feature — see
// docs/ENHANCEMENTS.md E-30.
export const EXTENDED_TOOL_PREFIXES = [
  "nuclei",
  "zap",
  "sqlmap",
  "xsser",
  "commix",
  "nmap",
  "subdomains",
  "deep-tls",
  "secretScan",
  "dependency-manifest",
  "docker-base-image",
  "auth-check",
] as const;

export function isExtendedToolFinding(checkId: string | undefined): boolean {
  if (!checkId) return false;
  return (EXTENDED_TOOL_PREFIXES as readonly string[]).includes(checkId.split(".")[0]);
}

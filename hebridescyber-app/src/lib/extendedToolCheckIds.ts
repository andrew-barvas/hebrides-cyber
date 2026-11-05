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
  "dalfox",
  "nmap",
  "subdomains",
  "deep-tls",
  "secretScan",
  "dependency-manifest",
  "docker-base-image",
  "trivy-image",
  "trivy-config",
  "sast",
  "workflow-security",
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
  "jwt-analysis",
  "cloudPosture",
  "http-probe",
  "content-discovery",
  "credential-spray",
  "strix",
  "cairn",
  "badsecrets",
  "katana",
  "network-exposure",
  "prowler",
] as const;

// Extended-tool checks whose namespace is shared with a base check, so the
// prefix alone can't tell them apart. The apiSpecInjection tool and the base
// suite's passive API-spec check both emit "api-spec.*"; only these three come
// from the injection tool (scanners/apiSpec.ts's checkApiSpecInjection). Without
// them, an on-demand scan's diff showed an API SQL injection as fixed.
export const EXTENDED_CHECK_BASES: ReadonlySet<string> = new Set(["api-spec.sqli", "api-spec.sqli-path", "api-spec.xss"]);

export function isExtendedToolFinding(checkId: string | undefined): boolean {
  if (!checkId) return false;
  // The signed-in crawl (crawl.auth.*) only runs in the extended suite; the anonymous crawl.* does not.
  if (checkId.startsWith("crawl.auth.")) return true;
  if (EXTENDED_CHECK_BASES.has(checkId.split(":")[0])) return true;
  return (EXTENDED_TOOL_PREFIXES as readonly string[]).includes(checkId.split(".")[0]);
}

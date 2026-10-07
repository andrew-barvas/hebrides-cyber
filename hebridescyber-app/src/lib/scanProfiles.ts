// Scan profiles: which of the extended-tool suite's tools run for a given
// scan. Replaces the old binary ExecuteScanOptions.runExtendedTools flag
// (all-or-nothing) with a named profile plus optional per-tool overrides —
// see scanExecution.ts's runExtendedTools() for where this is consumed.
//
// Deliberately excludes tools that don't exist in this codebase yet
// (Kiterunner, Arjun, Dalfox, WPScan CLI, CMSmap, Gospider, Photon,
// WhatWaf — see docs/24-FEATURE-EXPANSION-SPEC.md for that roadmap). Each
// future tool's own PR adds its own key here, in whichever profile(s) it
// belongs — additive, no restructuring, same precedent compliance.ts and
// fixDifficulty.ts already set for their own tables.

export type ExtendedToolName =
  | "nuclei"
  | "zap"
  | "sqlmap"
  | "commix"
  | "nmap"
  | "subdomains"
  | "deepTls"
  | "secretScan"
  | "dependencyManifest"
  | "dockerBaseImage"
  | "trivyImage"
  | "trivyConfig"
  | "sast"
  | "authCheck"
  | "whatwaf"
  | "wpscan"
  | "cmsmap"
  | "photon"
  | "gospider"
  | "zapAjaxSpider"
  | "metadataLeak"
  | "kiterunner"
  | "arjun"
  | "sessionCheck"
  | "cloudPosture"
  | "httpx"
  | "contentDiscovery"
  | "credentialSpray"
  | "strix"
  | "cairn"
  | "apiSpecInjection";

// Single source of truth for "what are the extended tools". `full` is
// DERIVED from this list (below), not hand-typed — a hand-typed literal is
// exactly how EXTENDED_TOOL_PREFIXES (extendedToolCheckIds.ts) missed
// trivy-image/trivy-config when Trivy was added to the suite. Deriving
// makes "full enables everything" a tautology by construction rather than
// something that needs constant vigilance as tools are added.
export const EXTENDED_TOOL_NAMES: readonly ExtendedToolName[] = [
  "nuclei",
  "zap",
  "sqlmap",
  "commix",
  "nmap",
  "subdomains",
  "deepTls",
  "secretScan",
  "dependencyManifest",
  "dockerBaseImage",
  "trivyImage",
  "trivyConfig",
  "sast",
  "authCheck",
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
  "httpx",
  "contentDiscovery",
  "credentialSpray",
  "strix",
  "cairn",
  "apiSpecInjection",
];

// The opt-in offensive suite: tools that generate brute-force or real attack
// traffic. They are gated to the Tier A `offensive` profile ONLY and are
// deliberately excluded from `full` (and every other profile), so a normal
// scheduled scan never runs them. strix/cairn (autonomous exploit agents),
// contentDiscovery (directory/vhost brute-force) and credentialSpray (login
// brute-force) all belong here. See docs/USER-GUIDE §6 and planAccess.ts.
export const OFFENSIVE_ONLY_TOOLS: ReadonlySet<ExtendedToolName> = new Set<ExtendedToolName>([
  "contentDiscovery",
  "credentialSpray",
  "strix",
  "cairn",
]);

export type ScanProfile = "safe" | "full" | "api" | "cms" | "osint" | "offensive" | "ai-pentest";

// A reasonable starting proposal for the api/cms/osint subsets, not a
// locked product decision — easy to adjust later since it's one config
// table with no other code depending on the exact membership.
const SCAN_PROFILES: Record<ScanProfile, Partial<Record<ExtendedToolName, boolean>>> = {
  safe: {},
  full: Object.fromEntries(EXTENDED_TOOL_NAMES.filter((n) => !OFFENSIVE_ONLY_TOOLS.has(n)).map((n) => [n, true])) as Record<ExtendedToolName, boolean>,
  // Request/response attack surface: injection + active scanning + authenticated headers.
  api: { nuclei: true, zap: true, sqlmap: true, commix: true, authCheck: true, whatwaf: true, zapAjaxSpider: true, kiterunner: true, arjun: true, sessionCheck: true, apiSpecInjection: true },
  // CMS-specific attack surface: nuclei's tech-scoped tags cover WP/Drupal/Joomla;
  // active scan + XSS are the classic CMS admin/comment-form vectors.
  cms: { nuclei: true, zap: true, authCheck: true, whatwaf: true, wpscan: true, cmsmap: true, zapAjaxSpider: true },
  // Passive reconnaissance / supply-chain inventory — no active exploitation.
  osint: {
    subdomains: true,
    deepTls: true,
    nmap: true,
    secretScan: true,
    dependencyManifest: true,
    dockerBaseImage: true,
    trivyImage: true,
    trivyConfig: true,
    sast: true,
    photon: true,
    gospider: true,
    metadataLeak: true,
    cloudPosture: true,
    httpx: true,
  },
  // Tier A opt-in offensive mode: the full active suite PLUS the offensive-only
  // tools (directory/vhost brute-force, login credential spraying, and the
  // autonomous exploit agents). Reachable ONLY by a Tier A account that has
  // recorded a per-scan authorization for the target (offensive_scan_authorizations)
  // against an ownership-verified domain — enforced in run-queued-scan-jobs.ts,
  // not here. credentialSpray/strix/cairn stay not_configured until the owner
  // supplies their inputs (a sacrificial test account / an LLM key), so enabling
  // the profile does not by itself fire a real attack.
  offensive: Object.fromEntries(EXTENDED_TOOL_NAMES.map((n) => [n, true])) as Record<ExtendedToolName, boolean>,
  // AI-powered pentest: runs Strix alongside the full active-scan suite.
  // Strix uses LLM inference ($2-5/scan), so this profile is gated to
  // Agency tier or higher — see docs/SPRINT-PLAN.md Sprint 18.
  "ai-pentest": {
    ...Object.fromEntries(EXTENDED_TOOL_NAMES.map((n) => [n, true])),
    strix: true,
  } as Record<ExtendedToolName, boolean>,
};

/**
 * Resolves a profile (plus optional bundle overrides) into a full,
 * all-14-keys-present tool-enable map. bundleOverrides, when given, win
 * over the base profile's own tool list — see scan_bundles (Item 3).
 */
export function resolveToolConfig(
  profile: ScanProfile,
  bundleOverrides?: Partial<Record<ExtendedToolName, boolean>>
): Record<ExtendedToolName, boolean> {
  const merged = { ...SCAN_PROFILES[profile], ...bundleOverrides };
  const result = {} as Record<ExtendedToolName, boolean>;
  for (const name of EXTENDED_TOOL_NAMES) {
    result[name] = merged[name] ?? false;
  }
  return result;
}

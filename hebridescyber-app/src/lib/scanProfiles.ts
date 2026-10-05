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
  | "xsser"
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
  "xsser",
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
  "strix",
  "cairn",
  "apiSpecInjection",
];

export type ScanProfile = "safe" | "full" | "api" | "cms" | "osint" | "ai-pentest";

// A reasonable starting proposal for the api/cms/osint subsets, not a
// locked product decision — easy to adjust later since it's one config
// table with no other code depending on the exact membership.
const SCAN_PROFILES: Record<ScanProfile, Partial<Record<ExtendedToolName, boolean>>> = {
  safe: {},
  full: Object.fromEntries(EXTENDED_TOOL_NAMES.filter((n) => n !== "strix" && n !== "cairn").map((n) => [n, true])) as Record<ExtendedToolName, boolean>,
  // Request/response attack surface: injection + active scanning + authenticated headers.
  api: { nuclei: true, zap: true, sqlmap: true, xsser: true, commix: true, authCheck: true, whatwaf: true, zapAjaxSpider: true, kiterunner: true, arjun: true, sessionCheck: true, apiSpecInjection: true },
  // CMS-specific attack surface: nuclei's tech-scoped tags cover WP/Drupal/Joomla;
  // active scan + XSS are the classic CMS admin/comment-form vectors.
  cms: { nuclei: true, zap: true, xsser: true, authCheck: true, whatwaf: true, wpscan: true, cmsmap: true, zapAjaxSpider: true },
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
  },
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

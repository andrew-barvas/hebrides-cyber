// Scan profiles: which of the extended-tool suite's tools run for a given
// scan. Replaces the old binary ExecuteScanOptions.runExtendedTools flag
// (all-or-nothing) with a named profile plus optional per-tool overrides —
// see scanExecution.ts's runExtendedTools() for where this is consumed.
//
// Each tool's own PR adds its own key here, in whichever profile(s) it
// belongs — additive, no restructuring, same precedent compliance.ts and
// fixDifficulty.ts already set for their own tables. This list used to also
// name Kiterunner, Arjun, WPScan CLI, CMSmap, Gospider, Photon, WhatWaf and
// Dalfox; all eight now exist and are wired.

export type ExtendedToolName =
  | "nuclei"
  | "zap"
  | "sqlmap"
  | "commix"
  | "dalfox"
  | "nmap"
  | "subdomains"
  | "deepTls"
  | "secretScan"
  | "dependencyManifest"
  | "dockerBaseImage"
  | "trivyImage"
  | "trivyConfig"
  | "sast"
  | "workflowSecurity"
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
  | "jwtAnalysis"
  | "cloudPosture"
  | "httpx"
  | "contentDiscovery"
  | "credentialSpray"
  | "strix"
  | "cairn"
  | "apiSpecInjection"
  | "badsecrets"
  | "katana"
  | "networkExposure"
  | "prowler";

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
  "dalfox",
  "nmap",
  "subdomains",
  "deepTls",
  "secretScan",
  "dependencyManifest",
  "dockerBaseImage",
  "trivyImage",
  "trivyConfig",
  "sast",
  "workflowSecurity",
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
  "jwtAnalysis",
  "cloudPosture",
  "httpx",
  "contentDiscovery",
  "credentialSpray",
  "strix",
  "cairn",
  "apiSpecInjection",
  "badsecrets",
  "katana",
  "networkExposure",
  "prowler",
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

// Tools that stay in the suite but are held OUT of the default `full` profile
// because they can't be verified against a hermetic local target in CI (they
// have no real-binary `*.integration.test.ts`), per CLAUDE.md rule 15: "take a
// tool out of the full profile rather than leave it unverified."
//   - wpscan / cmsmap: need a real WordPress/CMS target to exercise, which CI
//     has no hermetic fixture for; they remain in the opt-in, CMS-detection-
//     gated `cms` profile.
//   - photon: not installed anywhere. The PyPI `photon` package puts no
//     `photon` command on PATH, so photon.ts reports not_configured; it
//     remains in the opt-in `osint` profile for when a real install exists.
//   - sqlmap / commix / dalfox: owner decision 2026-10-30. They send injection
//     test payloads (SQL, OS-command and XSS probes) at the target, which is the
//     most intrusive thing the default profile did. The default profile now
//     keeps to detection and configuration checks; these remain available in
//     the opt-in `api` profile, and in offensive/ai-pentest.
// nmap, zap and arjun, which DO now have integration tests, stay in `full`.
// This only narrows `full`: a tool here is still reachable through whichever
// explicit profile lists it, and through offensive/ai-pentest (which spread
// every key). whatwaf's full-profile membership is handled separately.
export const EXCLUDED_FROM_FULL: ReadonlySet<ExtendedToolName> = new Set<ExtendedToolName>([
  "wpscan",
  "cmsmap",
  "photon",
  "sqlmap",
  "commix",
  "dalfox",
]);

export type ScanProfile = "safe" | "full" | "api" | "cms" | "osint" | "offensive" | "ai-pentest";

// A reasonable starting proposal for the api/cms/osint subsets, not a
// locked product decision — easy to adjust later since it's one config
// table with no other code depending on the exact membership.
const SCAN_PROFILES: Record<ScanProfile, Partial<Record<ExtendedToolName, boolean>>> = {
  safe: {},
  full: Object.fromEntries(EXTENDED_TOOL_NAMES.filter((n) => !OFFENSIVE_ONLY_TOOLS.has(n) && !EXCLUDED_FROM_FULL.has(n)).map((n) => [n, true])) as Record<ExtendedToolName, boolean>,
  // Request/response attack surface: injection + active scanning + authenticated headers.
  api: { nuclei: true, zap: true, sqlmap: true, commix: true, dalfox: true, authCheck: true, whatwaf: true, zapAjaxSpider: true, kiterunner: true, arjun: true, sessionCheck: true, jwtAnalysis: true, apiSpecInjection: true, badsecrets: true, katana: true },
  // CMS-specific attack surface: nuclei's tech-scoped tags cover WP/Drupal/Joomla;
  // active scan + XSS are the classic CMS admin/comment-form vectors.
  cms: { nuclei: true, zap: true, authCheck: true, whatwaf: true, wpscan: true, cmsmap: true, zapAjaxSpider: true, badsecrets: true },
  // Passive reconnaissance / supply-chain inventory — no active exploitation.
  osint: {
    subdomains: true,
    deepTls: true,
    nmap: true,
    networkExposure: true,
    secretScan: true,
    dependencyManifest: true,
    dockerBaseImage: true,
    trivyImage: true,
    trivyConfig: true,
    sast: true,
    workflowSecurity: true,
    photon: true,
    gospider: true,
    metadataLeak: true,
    cloudPosture: true,
    prowler: true,
    httpx: true,
    katana: true,
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
 * Resolves a profile (plus optional bundle overrides) into a tool-enable map
 * carrying every ExtendedToolName, present whether enabled or not.
 * bundleOverrides, when given, win over the base profile's own tool list —
 * see scan_bundles (Item 3). Deliberately names no count: the previous
 * "all-14-keys-present" wording went stale as tools were added.
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

/**
 * True when a resolved scan configuration would run any OFFENSIVE_ONLY_TOOLS,
 * and must therefore pass run-queued-scan-jobs.ts's Tier A + per-target
 * authorization gate before it runs.
 *
 * Derived from the resolved tool map, never from a list of profile names.
 * A `profile === "offensive"` check used to be the gate's condition, and it
 * missed `ai-pentest`, which spreads every tool key and so enables the same
 * four offensive-only tools; migration 051 made that value storable, and
 * MonitoredTargets.tsx writes scan_profile straight from the browser under
 * RLS with no server-side validation, so any owner could reach it. Deriving
 * the answer here means a new profile — or a scan bundle's tool_overrides —
 * that enables an offensive tool is gated automatically rather than silently
 * bypassing it.
 */
export function enablesOffensiveTools(
  profile: ScanProfile,
  bundleOverrides?: Partial<Record<ExtendedToolName, boolean>>
): boolean {
  const config = resolveToolConfig(profile, bundleOverrides);
  for (const tool of OFFENSIVE_ONLY_TOOLS) {
    if (config[tool]) return true;
  }
  return false;
}

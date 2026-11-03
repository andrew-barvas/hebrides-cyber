// Scanner-tool version pins and how to move them (src/scripts/update-scanner-tools.ts,
// .github/workflows/scanner-tool-updates.yml).
//
// The workflows stay the source of truth: every tool is pinned in place, as a
// `<ENV>_VERSION:` + `<ENV>_SHA256:` env pair, a `git clone --branch <tag>`, or a
// `pkg==<version>` pip install. This module knows where each pin lives and how
// to rewrite it; the script does the network part (release lists, downloading
// the asset to hash it, licence lookups) and calls in here.
//
// Rules an update must pass, all enforced by pickUpdate()/checkLicence():
// - Stable releases only (no drafts, prereleases or non-numeric tags).
// - At least MIN_RELEASE_AGE_DAYS old, so a compromised or broken release has
//   time to be noticed and pulled before a secret-holding scan job runs it.
// - Never a downgrade.
// - The upstream licence is unchanged from what was reviewed (`licence`). A
//   tool that relicenses (to source-available, or non-commercial) is held back
//   for a person to decide, rather than bumped silently.
//
// Pure, no Node imports, so it is unit-tested without the network.

export const MIN_RELEASE_AGE_DAYS = 14;

type Base = {
  /** Stable id used for branch names and `--tool`. */
  id: string;
  /** GitHub owner/repo: releases and the licence come from here. */
  repo: string;
  /** SPDX id the GitHub licence API reported when this pin was last reviewed. NOASSERTION = a custom licence text, reviewed by hand. */
  licence: string;
};

/** A release binary pinned as `<ENV>_VERSION` + `<ENV>_SHA256`. */
export type ReleaseAssetTool = Base & {
  kind: "release-asset";
  env: string;
  /** Whether the pinned value keeps the tag's leading "v" (NUCLEI_VERSION: v3.3.9 vs DALFOX_VERSION: 3.2.4). */
  keepV: boolean;
  /** The release asset's file name for a pinned value, mirroring the workflow's URL. */
  asset: (pinned: string) => string;
};

/** A `git clone --branch <tag> https://github.com/<repo>` pin, optionally also held in `<ENV>_VERSION`. */
export type GitTagTool = Base & { kind: "git-tag"; env?: string };

/** A `<package>==<version>` pip pin. */
export type PypiTool = Base & { kind: "pypi"; package: string };

/** A PyPI wheel downloaded by URL and pinned as `<ENV>_VERSION` + `<ENV>_SHA256`. */
export type PypiWheelTool = Base & { kind: "pypi-wheel"; package: string; env: string };

export type ScannerTool = ReleaseAssetTool | GitTagTool | PypiTool | PypiWheelTool;

const stripV = (v: string) => v.replace(/^v/, "");
const pd = (name: string) => (v: string) => `${name}_${stripV(v)}_linux_amd64.zip`;

export const SCANNER_TOOLS: readonly ScannerTool[] = [
  { id: "nuclei", kind: "release-asset", env: "NUCLEI", repo: "projectdiscovery/nuclei", licence: "MIT", keepV: true, asset: pd("nuclei") },
  { id: "subfinder", kind: "release-asset", env: "SUBFINDER", repo: "projectdiscovery/subfinder", licence: "MIT", keepV: true, asset: pd("subfinder") },
  { id: "httpx", kind: "release-asset", env: "HTTPX", repo: "projectdiscovery/httpx", licence: "MIT", keepV: true, asset: pd("httpx") },
  { id: "katana", kind: "release-asset", env: "KATANA", repo: "projectdiscovery/katana", licence: "MIT", keepV: true, asset: pd("katana") },
  { id: "naabu", kind: "release-asset", env: "NAABU", repo: "projectdiscovery/naabu", licence: "MIT", keepV: true, asset: pd("naabu") },
  { id: "ffuf", kind: "release-asset", env: "FFUF", repo: "ffuf/ffuf", licence: "MIT", keepV: false, asset: (v) => `ffuf_${v}_linux_amd64.tar.gz` },
  { id: "gitleaks", kind: "release-asset", env: "GITLEAKS", repo: "gitleaks/gitleaks", licence: "MIT", keepV: false, asset: (v) => `gitleaks_${v}_linux_x64.tar.gz` },
  { id: "trivy", kind: "release-asset", env: "TRIVY", repo: "aquasecurity/trivy", licence: "Apache-2.0", keepV: false, asset: (v) => `trivy_${v}_Linux-64bit.tar.gz` },
  { id: "opengrep", kind: "release-asset", env: "OPENGREP", repo: "opengrep/opengrep", licence: "LGPL-2.1", keepV: false, asset: () => "opengrep_manylinux_x86" },
  { id: "dalfox", kind: "release-asset", env: "DALFOX", repo: "hahwul/dalfox", licence: "MIT", keepV: false, asset: (v) => `dalfox-v${v}-linux-x86_64.tar.gz` },
  { id: "gospider", kind: "release-asset", env: "GOSPIDER", repo: "jaeles-project/gospider", licence: "MIT", keepV: false, asset: (v) => `gospider_v${v}_linux_x86_64.zip` },
  { id: "kiterunner", kind: "release-asset", env: "KITERUNNER", repo: "assetnote/kiterunner", licence: "AGPL-3.0", keepV: false, asset: (v) => `kiterunner_${v}_linux_amd64.tar.gz` },
  // Renamed x64 -> x86-64 after v12.2.3.
  {
    id: "postgrest",
    kind: "release-asset",
    env: "POSTGREST",
    repo: "PostgREST/postgrest",
    licence: "MIT",
    keepV: true,
    asset: (v) => `postgrest-${v}-linux-static-${compareVersions(v, "v12.2.3") > 0 ? "x86-64" : "x64"}.tar.xz`,
  },
  { id: "nuclei-templates", kind: "git-tag", env: "NUCLEI_TEMPLATES", repo: "projectdiscovery/nuclei-templates", licence: "MIT" },
  { id: "commix", kind: "git-tag", repo: "commixproject/commix", licence: "NOASSERTION" },
  { id: "whatwaf", kind: "git-tag", repo: "Ekultek/WhatWaf", licence: "NOASSERTION" },
  { id: "testssl", kind: "git-tag", repo: "testssl/testssl.sh", licence: "GPL-2.0" },
  { id: "zizmor", kind: "pypi", package: "zizmor", repo: "zizmorcore/zizmor", licence: "MIT" },
  { id: "badsecrets", kind: "pypi", package: "badsecrets", repo: "blacklanternsecurity/badsecrets", licence: "AGPL-3.0" },
  { id: "arjun", kind: "pypi", package: "arjun", repo: "s0md3v/Arjun", licence: "AGPL-3.0" },
  { id: "sqlmap", kind: "pypi", package: "sqlmap", repo: "sqlmapproject/sqlmap", licence: "NOASSERTION" },
  { id: "prowler", kind: "pypi-wheel", package: "prowler", env: "PROWLER", repo: "prowler-cloud/prowler", licence: "Apache-2.0" },
];

/**
 * Pinned elsewhere and deliberately not automated, with the reason. Reported
 * by the script so nobody assumes they are covered.
 */
export const NOT_AUTOMATED: ReadonlyArray<{ tool: string; reason: string }> = [
  { tool: "wpscan", reason: "gem pin; every 4.x needs Ruby >= 3.3 and the runner has 3.2, so it is held at 3.8.28 (see tool-integration.yml)" },
  { tool: "zaproxy", reason: "Docker image pinned by digest; bump by hand from the release notes" },
  { tool: "nmap, hydra", reason: "installed from the runner's signed apt repository, not pinned" },
];

export type Release = { tag: string; publishedAt: string; prerelease?: boolean; draft?: boolean };

const NUMERIC_TAG = /^v?\d+(\.\d+)*$/;

/** Numeric, segment-wise comparison of versions such as "v1.10.2" and "1.9". */
export function compareVersions(a: string, b: string): number {
  const pa = stripV(a).split(".").map(Number);
  const pb = stripV(b).split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/**
 * The newest release that is stable, old enough and newer than `current`, or
 * null. `current` is compared without its "v", so a tool whose tags changed
 * style ("1.8" then "v1.9") still compares correctly.
 */
export function pickUpdate(releases: readonly Release[], current: string, now: Date, minAgeDays = MIN_RELEASE_AGE_DAYS): Release | null {
  const cutoff = now.getTime() - minAgeDays * 86_400_000;
  const eligible = releases.filter(
    (r) => !r.prerelease && !r.draft && NUMERIC_TAG.test(r.tag) && Date.parse(r.publishedAt) <= cutoff && compareVersions(r.tag, current) > 0,
  );
  if (eligible.length === 0) return null;
  return eligible.reduce((best, r) => (compareVersions(r.tag, best.tag) > 0 ? r : best));
}

/** null when the licence matches what was reviewed, else why the update is held. */
export function checkLicence(tool: ScannerTool, upstreamSpdx: string | null): string | null {
  if (!upstreamSpdx) return `could not read the upstream licence of ${tool.repo}`;
  return upstreamSpdx === tool.licence ? null : `licence changed from ${tool.licence} to ${upstreamSpdx}; review before updating`;
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** The value a release tag is pinned as in the workflows. */
export function pinnedValue(tool: ScannerTool, tag: string): string {
  return tool.kind === "release-asset" && tool.keepV ? tag : tool.kind === "git-tag" ? tag : stripV(tag);
}

/** The release tag a pinned value came from (release-asset tools only). */
export function tagFor(tool: ReleaseAssetTool, pinned: string): string {
  return tool.keepV ? pinned : `v${pinned}`;
}

export function releaseAssetUrl(tool: ReleaseAssetTool, pinned: string): string {
  return `https://github.com/${tool.repo}/releases/download/${tagFor(tool, pinned)}/${tool.asset(pinned)}`;
}

function cloneRe(tool: GitTagTool): RegExp {
  return new RegExp(`--branch\\s+"?([^\\s"]+)"?\\s+https://github\\.com/${esc(tool.repo)}(?:\\.git)?\\b`, "g");
}

/** Every pinned value for this tool in one workflow file (normally one distinct value). */
export function readPins(tool: ScannerTool, text: string): string[] {
  const found = new Set<string>();
  const add = (re: RegExp) => {
    for (const m of text.matchAll(re)) found.add(m[1]);
  };
  if (tool.kind === "pypi") add(new RegExp(`\\b${esc(tool.package)}==([0-9][^\\s"'\\\\]*)`, "g"));
  else if (tool.kind === "git-tag") {
    if (tool.env) add(new RegExp(`^\\s*${tool.env}_VERSION:\\s*["']?([^\\s"']+)`, "gm"));
    // A clone through the env var (`--branch "${X_VERSION}"`) carries no literal tag.
    for (const m of text.matchAll(cloneRe(tool))) if (!m[1].startsWith("$")) found.add(m[1]);
  } else add(new RegExp(`^\\s*${tool.env}_VERSION:\\s*["']?([^\\s"']+)`, "gm"));
  return [...found];
}

export type PinUpdate = { version: string; sha256?: string; wheelUrl?: string };

/** Rewrite every pin of `tool` in a workflow file. Returns the text unchanged when it holds none. */
export function applyUpdate(tool: ScannerTool, text: string, update: PinUpdate): string {
  const { version } = update;
  const env = "env" in tool ? tool.env : undefined;
  const setEnv = (t: string, suffix: "VERSION" | "SHA256", value: string) =>
    t.replace(new RegExp(`^(\\s*${env}_${suffix}:\\s*)(["']?)[^\\s"']+\\2`, "gm"), `$1$2${value}$2`);

  if (tool.kind === "pypi") {
    return text.replace(new RegExp(`\\b(${esc(tool.package)}==)[0-9][^\\s"'\\\\]*`, "g"), `$1${version}`);
  }
  if (tool.kind === "git-tag") {
    const olds = readPins(tool, text);
    let out = tool.env ? setEnv(text, "VERSION", version) : text;
    out = out.replace(cloneRe(tool), (m, tag: string) => (tag.startsWith("$") ? m : m.replace(tag, version)));
    // Checks that assert the cloned tag (`... --exact-match)" = "v3.2.4"`).
    for (const old of olds) out = out.replace(new RegExp(`(--exact-match\\)"\\s*=\\s*")${esc(old)}"`, "g"), `$1${version}"`);
    return out;
  }
  if (!update.sha256 || !/^[0-9a-f]{64}$/.test(update.sha256)) throw new Error(`${tool.id}: a SHA-256 is required to move a checksum pin`);
  const olds = readPins(tool, text);
  let out = setEnv(setEnv(text, "VERSION", version), "SHA256", update.sha256);
  if (tool.kind === "release-asset") {
    // An upstream asset rename (PostgREST's x64 -> x86-64): the workflow's URL
    // spells the name with a ${ENV_VERSION} placeholder, so rewrite that template.
    const template = (v: string) => tool.asset(v).split(v).join(`\${${tool.env}_VERSION}`);
    for (const old of olds) {
      const from = template(old);
      const to = template(version);
      // Only names that carry the pinned value verbatim can be matched as a template.
      if (from !== to && from.includes("${")) out = out.split(from).join(to);
    }
  }
  if (tool.kind === "pypi-wheel") {
    if (!update.wheelUrl) throw new Error(`${tool.id}: the wheel URL is required`);
    // The URL's path holds a content hash, so it changes with every release; the
    // file name keeps its ${ENV}_VERSION placeholder.
    const placeholder = `${tool.package}-\${${tool.env}_VERSION}-`;
    const newUrl = update.wheelUrl.replace(`${tool.package}-${version}-`, placeholder);
    out = out.replace(new RegExp(`https://files\\.pythonhosted\\.org/packages/[^"\\s]*/${esc(placeholder)}[^"\\s]*\\.whl`, "g"), newUrl);
  }
  return out;
}

/** Markdown for the pull request an update opens. */
export function prBody(tool: ScannerTool, from: string, to: string, release: Release, sha256?: string): string {
  return [
    `Bumps **${tool.id}** from \`${from}\` to \`${to}\` (released ${release.publishedAt.slice(0, 10)}, upstream licence ${tool.licence} unchanged).`,
    "",
    `Release notes: https://github.com/${tool.repo}/releases/tag/${release.tag}`,
    sha256 ? `New SHA-256 (computed from the downloaded asset): \`${sha256}\`` : "",
    "",
    "Opened by `.github/workflows/scanner-tool-updates.yml`. The tool's real-binary integration tests (`tool-integration.yml`) run on this PR; a parser or flag change shows up there. If they fail, the weekly Claude maintenance routine (or a session) fixes the wrapper and fixtures on this branch. Never merged automatically.",
  ]
    .filter((l, i, a) => l !== "" || a[i - 1] !== "")
    .join("\n");
}

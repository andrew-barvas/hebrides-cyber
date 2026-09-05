// Trivy integration — real container base-image CVE scanning and IaC
// misconfiguration scanning for a connected GitHub repo. Two modes, one
// file: both need `githubRepo`, so both live here in src/lib/scanners/
// rather than src/worker/tools/ (the location/wiring pattern is dictated by
// the repo-gating, even though both internally shell out via execFile like
// the worker/tools/*.ts wrappers do).
//
// Fills the exact gap dockerBaseImage.ts's own header comment identifies
// and explicitly declines to fill: "Getting that [installed-package]
// manifest means pulling the actual image and inspecting its package
// database (what grype/trivy/syft do) — a materially heavier feature...
// and out of scope for this module." This module is that heavier feature.
//
// Deliberately NOT in scope: real cloud-account posture scanning (AWS/
// Azure/GCP IAM, security groups) — that needs a customer credential grant
// this app has no onboarding flow for at all, tracked separately as
// docs/ENHANCEMENTS.md E-32. Also not in scope: building the customer's own
// application image from their Dockerfile — meaningfully heavier and
// riskier (running an arbitrary customer's build steps in CI) than pulling
// a public base image by name. Image mode only ever pulls the named base
// image (node:20-alpine, etc.), never anything the customer built.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "./index";
import { resolveGithubAuth } from "../githubApp";
import { parseDockerfileStages, resolveBaseImages } from "./dockerBaseImage";
import { trivyImagePackageRemediation, trivyConfigMisconfigRemediation } from "./remediationText";

const execFileAsync = promisify(execFile);

const githubApi = "https://api.github.com";
const GITHUB_API_TIMEOUT_MS = 10_000;
const TRIVY_IMAGE_TIMEOUT_MS = 180_000; // matches sqlmap.ts's upper end
const TRIVY_CONFIG_TIMEOUT_MS = 120_000; // matches secretScan.ts's clone+scan budget
const CLONE_TIMEOUT_MS = 60_000; // config mode only ever needs a shallow, no-history checkout

function ghHeaders(token: string): Record<string, string> {
  return {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

type ExecFailure = { code?: string | number; killed?: boolean; signal?: string | null; message?: string };

function isMissingBinary(err: ExecFailure): boolean {
  return err.code === "ENOENT";
}

// The clone URL embeds the token — never let it leak into a stored note.
function sanitiseForOutput(text: string, token: string): string {
  return token ? text.split(token).join("[redacted]") : text;
}

// ============================================================================
// Image mode — pulls and scans the Dockerfile's final-stage base image only
// (dockerBaseImage.ts's own EOL heuristic already covers every stage; a real
// registry pull + CVE-DB match is worth reserving for the image that
// actually ships).
// ============================================================================

export type TrivyImageOptions = {
  /** null/empty when the scan owner has no repo_connections row. */
  githubRepo: string | null | undefined;
  /** Defaults to src/lib/githubApp.ts's resolveGithubAuth() result (App token or GITHUB_PAT). Override only for tests/local verification. */
  githubToken?: string;
};

export type TrivyImageResult =
  | { status: "completed"; repo: string; imageRef: string; findings: Finding[]; note?: string }
  | { status: "not_applicable"; repo: string; findings: []; note: string }
  | { status: "not_configured"; repo: string; findings: []; note: string }
  | { status: "error"; repo: string; findings: []; note: string };

async function fetchDockerfile(githubRepo: string, token: string): Promise<string | null> {
  for (const path of ["Dockerfile", "dockerfile"]) {
    try {
      const res = await fetch(`${githubApi}/repos/${githubRepo}/contents/${path}`, {
        headers: ghHeaders(token),
        signal: AbortSignal.timeout(GITHUB_API_TIMEOUT_MS),
      });
      if (!res.ok) continue;
      const body = (await res.json()) as { content?: string; encoding?: string };
      if (!body.content) continue;
      return Buffer.from(body.content, (body.encoding as BufferEncoding) ?? "base64").toString("utf-8");
    } catch {
      continue;
    }
  }
  return null;
}

type TrivyImageReport = {
  Results?: Array<{
    Target?: string;
    Vulnerabilities?: Array<{
      VulnerabilityID?: string;
      PkgName?: string;
      InstalledVersion?: string;
      FixedVersion?: string;
      Severity?: string;
      Title?: string;
    }>;
  }>;
};

const CVE_ID_PATTERN = /^CVE-\d{4}-\d+$/i;

function trivySeverityToFinding(severity: string | undefined): Finding["severity"] {
  switch ((severity ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "info";
  }
}

/**
 * Exported for local verification without a real trivy binary/registry
 * pull: pure JSON-in, Finding[]-out, same rationale as
 * dockerBaseImage.ts's buildDockerBaseImageFindings.
 */
export function buildTrivyImageFindings(report: TrivyImageReport, imageRef: string): Finding[] {
  const findings: Finding[] = [];
  for (const result of report.Results ?? []) {
    for (const v of result.Vulnerabilities ?? []) {
      if (!v.VulnerabilityID || !v.PkgName) continue;
      const cveIds = CVE_ID_PATTERN.test(v.VulnerabilityID) ? [v.VulnerabilityID.toUpperCase()] : undefined;
      findings.push({
        checkId: `trivy-image.vulnerable-package:${v.VulnerabilityID}:${v.PkgName}`,
        severity: trivySeverityToFinding(v.Severity),
        title: `[Trivy] ${v.VulnerabilityID} in ${v.PkgName} (${imageRef})`,
        detail:
          `${v.Title ?? "Known vulnerability"} — package "${v.PkgName}" ${v.InstalledVersion ?? "unknown version"} ` +
          `in base image "${imageRef}" is affected by ${v.VulnerabilityID}.`,
        remediation: trivyImagePackageRemediation(v.PkgName, v.InstalledVersion ?? "unknown", v.FixedVersion, imageRef),
        ...(cveIds ? { cveIds } : {}),
      });
    }
  }
  return findings;
}

export async function scanTrivyImage(options: TrivyImageOptions): Promise<TrivyImageResult> {
  const githubRepo = options.githubRepo || null;

  if (!githubRepo) {
    return { status: "not_applicable", repo: "", findings: [], note: "no repository connected — see /account to connect one." };
  }
  if (!/^[\w.-]+\/[\w.-]+$/.test(githubRepo)) {
    return { status: "not_applicable", repo: githubRepo, findings: [], note: "connected githubRepo is not a valid 'owner/repo' — reconnect via /account." };
  }
  const token = options.githubToken ?? (await resolveGithubAuth(githubRepo)).token;
  if (!token) {
    return { status: "not_configured", repo: githubRepo, findings: [], note: "No GitHub access configured (neither a GitHub App installation nor GITHUB_PAT) — skipping Trivy image scan. See .env.example." };
  }

  const dockerfile = await fetchDockerfile(githubRepo, token);
  if (!dockerfile) {
    return { status: "not_applicable", repo: githubRepo, findings: [], note: "No Dockerfile found at the repository root — nothing to scan." };
  }

  const stages = parseDockerfileStages(dockerfile);
  const images = resolveBaseImages(stages);
  const finalImage = images.find((i) => i.isFinalStage) ?? images[0];
  if (!finalImage) {
    return { status: "not_applicable", repo: githubRepo, findings: [], note: "Dockerfile has no FROM instruction — nothing to scan." };
  }

  try {
    const { stdout } = await execFileAsync(
      "trivy",
      [
        "image", finalImage.imageRef,
        "--format", "json",
        "--severity", "HIGH,CRITICAL",
        "--quiet",
        "--timeout", "150s", // kept under TRIVY_IMAGE_TIMEOUT_MS so trivy exits with its own message before Node SIGTERMs it
      ],
      { timeout: TRIVY_IMAGE_TIMEOUT_MS, maxBuffer: 20 * 1024 * 1024 }
    );

    const report = JSON.parse(stdout) as TrivyImageReport;
    const findings = buildTrivyImageFindings(report, finalImage.imageRef);
    return { status: "completed", repo: githubRepo, imageRef: finalImage.imageRef, findings };
  } catch (err) {
    const failure = err as ExecFailure;
    if (isMissingBinary(failure)) {
      return { status: "not_configured", repo: githubRepo, findings: [], note: "trivy is not installed in this environment — skipping image scan." };
    }
    return { status: "error", repo: githubRepo, findings: [], note: `trivy image scan of ${finalImage.imageRef} failed: ${failure.message ?? "unknown error"}` };
  }
}

// ============================================================================
// Config mode — clones the connected repo (shallow, current tree only — no
// history needed for IaC misconfiguration checks, unlike secretScan.ts's
// full-history clone) and runs `trivy config` for Terraform/Kubernetes/
// Dockerfile misconfigurations.
// ============================================================================

export type TrivyConfigOptions = {
  githubRepo: string | null | undefined;
  githubToken?: string;
};

export type TrivyConfigResult =
  | { status: "completed"; repo: string; findings: Finding[]; note?: string }
  | { status: "not_applicable"; repo: string; findings: []; note: string }
  | { status: "not_configured"; repo: string; findings: []; note: string }
  | { status: "error"; repo: string; findings: []; note: string };

async function cloneRepositoryShallow(githubRepo: string, token: string, dir: string): Promise<void> {
  const url = `https://x-access-token:${token}@github.com/${githubRepo}.git`;
  await execFileAsync(
    "git",
    [
      "-c", "credential.helper=",
      "clone",
      "--quiet",
      "--depth", "1",
      "--no-recurse-submodules",
      url,
      dir,
    ],
    {
      timeout: CLONE_TIMEOUT_MS,
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_ASKPASS: "echo", GCM_INTERACTIVE: "never" },
    }
  );
}

type TrivyConfigReport = {
  Results?: Array<{
    Target?: string;
    Type?: string;
    Misconfigurations?: Array<{
      ID?: string;
      Title?: string;
      Message?: string;
      Severity?: string;
      Resolution?: string;
      PrimaryURL?: string;
    }>;
  }>;
};

/**
 * Exported for local verification without a real trivy binary/clone: pure
 * JSON-in, Finding[]-out, same rationale as buildTrivyImageFindings above.
 */
export function buildTrivyConfigFindings(report: TrivyConfigReport): Finding[] {
  const findings: Finding[] = [];
  for (const result of report.Results ?? []) {
    const target = result.Target ?? "unknown file";
    for (const m of result.Misconfigurations ?? []) {
      if (!m.ID) continue;
      findings.push({
        checkId: `trivy-config.misconfiguration:${m.ID}:${target}`,
        severity: trivySeverityToFinding(m.Severity),
        title: `[Trivy] ${m.Title ?? m.ID} (${target})`,
        detail: m.Message ?? `${result.Type ?? "Config"} misconfiguration ${m.ID} found in ${target}.`,
        remediation: trivyConfigMisconfigRemediation(m.Resolution, m.PrimaryURL),
      });
    }
  }
  return findings;
}

export async function scanTrivyConfig(options: TrivyConfigOptions): Promise<TrivyConfigResult> {
  const githubRepo = options.githubRepo || null;

  if (!githubRepo) {
    return { status: "not_applicable", repo: "", findings: [], note: "no repository connected — see /account to connect one." };
  }
  if (!/^[\w.-]+\/[\w.-]+$/.test(githubRepo)) {
    return { status: "not_applicable", repo: githubRepo, findings: [], note: "connected githubRepo is not a valid 'owner/repo' — reconnect via /account." };
  }
  const token = options.githubToken ?? (await resolveGithubAuth(githubRepo)).token;
  if (!token) {
    return { status: "not_configured", repo: githubRepo, findings: [], note: "No GitHub access configured (neither a GitHub App installation nor GITHUB_PAT) — skipping Trivy config scan. See .env.example." };
  }

  let workDir: string | null = null;
  try {
    workDir = await mkdtemp(join(tmpdir(), "hebridescyber-trivy-"));
  } catch (err) {
    return { status: "error", repo: githubRepo, findings: [], note: `could not create temp directory: ${(err as Error).message}` };
  }

  const cloneDir = join(workDir, "repo");
  try {
    try {
      await cloneRepositoryShallow(githubRepo, token, cloneDir);
    } catch (err) {
      const failure = err as ExecFailure;
      if (isMissingBinary(failure)) {
        return { status: "not_configured", repo: githubRepo, findings: [], note: "git is not installed in this environment — skipping Trivy config scan." };
      }
      return { status: "error", repo: githubRepo, findings: [], note: sanitiseForOutput(`could not clone ${githubRepo}: ${failure.message ?? "unknown git error"}`, token) };
    }

    try {
      const { stdout } = await execFileAsync(
        "trivy",
        ["config", cloneDir, "--format", "json", "--severity", "MEDIUM,HIGH,CRITICAL", "--quiet"],
        { timeout: TRIVY_CONFIG_TIMEOUT_MS, maxBuffer: 20 * 1024 * 1024 }
      );
      const report = JSON.parse(stdout) as TrivyConfigReport;
      const findings = buildTrivyConfigFindings(report);
      return { status: "completed", repo: githubRepo, findings };
    } catch (err) {
      const failure = err as ExecFailure;
      if (isMissingBinary(failure)) {
        return { status: "not_configured", repo: githubRepo, findings: [], note: "trivy is not installed in this environment — skipping config scan." };
      }
      return { status: "error", repo: githubRepo, findings: [], note: `trivy config scan failed: ${failure.message ?? "unknown error"}` };
    }
  } finally {
    if (workDir) await rm(workDir, { recursive: true, force: true }).catch(() => undefined);
  }
}

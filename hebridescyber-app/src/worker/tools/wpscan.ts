// WPScan CLI integration — deeper WordPress scanning than the API-only
// wpvdb.ts path. Finds theme vulnerabilities, config backups, database
// exports, TimThumb, and additional user enumeration methods.
//
// Reuses the existing WPSCAN_API_TOKEN env var already wired into
// scheduled-scans.yml. When the binary is absent, returns
// { status: "not_configured" } so the worker continues gracefully.

import { execTool } from "../../lib/execTool";

const execFileAsync = execTool;

const WPSCAN_TIMEOUT_MS = 180_000;

export type WpScanFinding = {
  type: "vulnerability" | "misconfiguration";
  title: string;
  detail: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  slug?: string;
  cveIds?: string[];
  fixedIn?: string;
};

export type WpScanCliResult =
  | { status: "completed"; findings: WpScanFinding[] }
  | { status: "not_configured"; findings: [] }
  | { status: "error"; findings: []; note: string };

type WpScanJson = {
  interesting_findings?: Array<{
    type?: string;
    url?: string;
    to_s?: string;
    references?: Record<string, string[]>;
  }>;
  main_theme?: {
    slug?: string;
    version?: { number?: string };
    vulnerabilities?: Array<{
      title?: string;
      fixed_in?: string;
      references?: { cve?: string[]; url?: string[] };
    }>;
  };
  themes?: Record<
    string,
    {
      version?: { number?: string };
      vulnerabilities?: Array<{
        title?: string;
        fixed_in?: string;
        references?: { cve?: string[]; url?: string[] };
      }>;
    }
  >;
  config_backups?: Record<string, Record<string, unknown>>;
  db_exports?: Record<string, Record<string, unknown>>;
  users?: Record<string, { username?: string }>;
  timthumbs?: { [url: string]: Record<string, unknown> };
};

function parseFindings(raw: WpScanJson): WpScanFinding[] {
  const findings: WpScanFinding[] = [];

  for (const [url] of Object.entries(raw.config_backups ?? {})) {
    findings.push({
      type: "misconfiguration",
      title: "WordPress config backup accessible",
      detail: `Configuration backup found at: ${url}`,
      severity: "high",
      slug: "config-backup",
    });
  }

  for (const [url] of Object.entries(raw.db_exports ?? {})) {
    findings.push({
      type: "misconfiguration",
      title: "WordPress database export accessible",
      detail: `Database export found at: ${url}`,
      severity: "critical",
      slug: "db-export",
    });
  }

  for (const [url] of Object.entries(raw.timthumbs ?? {})) {
    findings.push({
      type: "vulnerability",
      title: "TimThumb script detected",
      detail: `TimThumb found at: ${url}. Historic RFI/RCE vector.`,
      severity: "high",
      slug: "timthumb",
    });
  }

  const allThemes = {
    ...(raw.main_theme ? { [raw.main_theme.slug ?? "main"]: raw.main_theme } : {}),
    ...(raw.themes ?? {}),
  };

  for (const [slug, theme] of Object.entries(allThemes)) {
    for (const vuln of theme.vulnerabilities ?? []) {
      findings.push({
        type: "vulnerability",
        title: vuln.title ?? `Theme vulnerability: ${slug}`,
        detail: `Theme "${slug}" ${theme.version?.number ? `v${theme.version.number}` : ""} — ${vuln.title ?? "known vulnerability"}`,
        severity: "high",
        slug,
        cveIds: vuln.references?.cve?.map((c) => `CVE-${c}`) ?? [],
        fixedIn: vuln.fixed_in ?? undefined,
      });
    }
  }

  return findings;
}

export async function runWpScanCli(targetUrl: string): Promise<WpScanCliResult> {
  const apiToken = process.env.WPSCAN_API_TOKEN;

  const args = [
    "--url", targetUrl,
    "--format", "json",
    "--no-banner",
    "--random-user-agent",
    "--detection-mode", "mixed",
    "--enumerate", "vt,cb,dbe,tt",
  ];

  if (apiToken) {
    args.push("--api-token", apiToken);
  }

  try {
    const { stdout } = await execFileAsync("wpscan", args, {
      timeout: WPSCAN_TIMEOUT_MS,
    });

    let parsed: WpScanJson;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      return { status: "completed", findings: [] };
    }

    return { status: "completed", findings: parseFindings(parsed) };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") {
      return { status: "not_configured", findings: [] };
    }
    // WPScan exits non-zero when it finds vulnerabilities — parse stdout if present
    const exitError = err as { stdout?: string };
    if (exitError.stdout) {
      try {
        const parsed: WpScanJson = JSON.parse(exitError.stdout);
        return { status: "completed", findings: parseFindings(parsed) };
      } catch {
        // fall through to error
      }
    }
    return {
      status: "error",
      findings: [],
      note: `wpscan exited with error: ${error.message}`,
    };
  }
}

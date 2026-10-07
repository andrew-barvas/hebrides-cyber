// CMSmap integration — CMS-specific vulnerability scanning for WordPress,
// Joomla, and Drupal. Complements WPScan (WordPress-only) with broader
// CMS coverage.
//
// When the binary is absent, returns { status: "not_configured" } so the
// worker continues gracefully.

import { execTool } from "../../lib/execTool";
import { readFile, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";

const execFileAsync = execTool;

const CMSMAP_TIMEOUT_MS = 150_000;

export type CmsMapFinding = {
  type: "vulnerability" | "misconfiguration";
  title: string;
  detail: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  checkName?: string;
  cveIds?: string[];
};

export type CmsMapResult =
  | { status: "completed"; cmsType: string; findings: CmsMapFinding[] }
  | { status: "not_configured"; findings: [] }
  | { status: "not_applicable"; findings: []; note: string }
  | { status: "error"; findings: []; note: string };

const CMS_FLAG: Record<string, string> = {
  wordpress: "W",
  joomla: "J",
  drupal: "D",
};

function parseSeverity(line: string): CmsMapFinding["severity"] {
  const lower = line.toLowerCase();
  if (lower.includes("[critical]") || lower.includes("rce") || lower.includes("remote code")) return "critical";
  if (lower.includes("[high]") || lower.includes("sql injection") || lower.includes("file upload")) return "high";
  if (lower.includes("[medium]") || lower.includes("[warning]")) return "medium";
  if (lower.includes("[low]") || lower.includes("[info]")) return "low";
  return "medium";
}

function parseStdoutFindings(stdout: string, cmsType: string): CmsMapFinding[] {
  const findings: CmsMapFinding[] = [];
  const lines = stdout.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // CMSmap outputs lines like "[I] 200 /administrator/" or "[!] Vulnerability found: ..."
    if (trimmed.startsWith("[!]") || trimmed.includes("vulnerability") || trimmed.includes("exploit")) {
      const cveMatch = trimmed.match(/CVE-\d{4}-\d{4,}/g);
      findings.push({
        type: "vulnerability",
        title: `[CMSmap] ${cmsType} vulnerability detected`,
        detail: trimmed.replace(/^\[!]\s*/, ""),
        severity: parseSeverity(trimmed),
        cveIds: cveMatch ?? [],
      });
    } else if (trimmed.includes("debug") || trimmed.includes("backup") || trimmed.includes("config")) {
      if (trimmed.startsWith("[I]") && (trimmed.includes("200") || trimmed.includes("found"))) {
        findings.push({
          type: "misconfiguration",
          title: `[CMSmap] ${cmsType} misconfiguration`,
          detail: trimmed.replace(/^\[I]\s*/, ""),
          severity: "medium",
          checkName: "misconfiguration",
        });
      }
    }
  }

  return findings;
}

export async function runCmsMap(
  targetUrl: string,
  cmsType: string
): Promise<CmsMapResult> {
  const flag = CMS_FLAG[cmsType.toLowerCase()];
  if (!flag) {
    return {
      status: "not_applicable",
      findings: [],
      note: `CMSmap does not support CMS type: ${cmsType}`,
    };
  }

  const outFile = `/tmp/cmsmap-${randomUUID()}.txt`;

  try {
    const { stdout } = await execFileAsync(
      "cmsmap",
      ["-t", targetUrl, "-f", flag, "-o", outFile],
      { timeout: CMSMAP_TIMEOUT_MS }
    );

    let fileContent = "";
    try {
      fileContent = await readFile(outFile, "utf8");
    } catch {
      // No output file — parse stdout instead
    }

    const findings = parseStdoutFindings(
      fileContent || stdout,
      cmsType
    );

    return { status: "completed", cmsType, findings };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") {
      return { status: "not_configured", findings: [] };
    }
    return {
      status: "error",
      findings: [],
      note: `cmsmap exited with error: ${error.message}`,
    };
  } finally {
    unlink(outFile).catch(() => undefined);
  }
}

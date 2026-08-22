// Nuclei scanner integration.
//
// Uses the nuclei binary (pinned to v3.3.9 in worker.Dockerfile). When the
// binary is absent, returns { status: "not_configured" } so the worker
// continues gracefully instead of failing the whole scan job.
//
// targetUrl has already been SSRF-validated by run-scan before it was
// enqueued — the worker trusts it.
//
// TEMPLATE CURATION (Sprint 5). Previously ran with no -tags filter at all —
// nuclei's entire default template set (thousands of templates spanning
// every CMS/framework/CVE it has ever gained a template for) fired against
// every target regardless of what's actually running there. Slow, and the
// signal-to-noise ratio suffers when most templates can never match.
//
// Now scoped by the technologies fingerprint.ts already detected
// (TECH_TAG_MAP below), plus a fixed baseline of high-value generic tags
// that apply regardless of any specific software (cve/exposure/misconfig/
// default-login/takeover) — so a target with zero detectable/mappable
// technology still gets a real, useful nuclei pass, never zero effective
// tags. TECH_TAG_MAP is a best-effort mapping to nuclei's own
// community-maintained tag vocabulary: an entry that doesn't match any real
// template just contributes nothing to -tags' OR-match, exactly as
// harmless as a technology this map doesn't cover at all — never an error,
// never a reason to fall back to the unscoped (slow, noisy) behaviour.

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";

const execFileAsync = promisify(execFile);

const NUCLEI_TIMEOUT_MS = 120_000; // 120 seconds

// Deliberately excludes pure analytics/marketing/CDN/WAF detections
// (Google Analytics, Hotjar, Cloudflare, Akamai, Vercel, Squarespace, …) —
// nuclei has essentially no attack templates for "a site uses this CDN,"
// only for self-hosted software with patchable versions. Mapping those
// anyway would waste query time on tags nuclei can't usefully act on.
const TECH_TAG_MAP: Record<string, string[]> = {
  Apache: ["apache"],
  Nginx: ["nginx"],
  IIS: ["iis"],
  PHP: ["php"],
  "ASP.NET": ["aspnet", "dotnet"],
  "Node.js": ["node", "nodejs"],
  WordPress: ["wordpress", "wp-plugin"],
  Drupal: ["drupal"],
  Joomla: ["joomla"],
  Magento: ["magento"],
  Ghost: ["ghost"],
  Laravel: ["laravel"],
  Django: ["django"],
  "Ruby on Rails": ["rails"],
  "Next.js": ["nextjs"],
  "Nuxt.js": ["nuxt"],
  jQuery: ["jquery"],
};

// Always included, regardless of detected technology — broad, well-
// established nuclei tag categories that find real issues on any target
// (exposed panels/files, generic misconfigurations, default credentials,
// subdomain takeovers, CVE-tagged templates that match on product
// signatures nuclei detects itself rather than needing our own hint).
const BASELINE_TAGS = ["cve", "exposure", "misconfig", "default-login", "takeover"];

function buildTagArgument(detectedTechnologies: string[]): string {
  const mapped = detectedTechnologies.flatMap((name) => TECH_TAG_MAP[name] ?? []);
  return [...new Set([...BASELINE_TAGS, ...mapped])].join(",");
}

export type NucleiFinding = {
  severity: string;
  title: string;
  detail: string;
  templateId: string;
};

export type NucleiResult =
  | { status: "completed"; findings: NucleiFinding[] }
  | { status: "not_configured"; findings: [] }
  | { status: "error"; findings: []; note: string };

type NucleiJsonEntry = {
  "template-id"?: string;
  info?: {
    name?: string;
    severity?: string;
    description?: string;
  };
  "matched-at"?: string;
  description?: string;
};

export async function runNuclei(targetUrl: string, detectedTechnologies: string[] = []): Promise<NucleiResult> {
  const tmpFile = `/tmp/nuclei-${randomUUID()}.json`;
  const tags = buildTagArgument(detectedTechnologies);

  try {
    await execFileAsync(
      "nuclei",
      [
        "-target", targetUrl,
        "-tags", tags,
        "-json-export", tmpFile,
        "-silent",
        "-timeout", "120",
      ],
      { timeout: NUCLEI_TIMEOUT_MS }
    );

    let raw: string;
    try {
      raw = await readFile(tmpFile, "utf8");
    } catch {
      // nuclei ran but produced no output file — no findings
      return { status: "completed", findings: [] };
    }

    const findings: NucleiFinding[] = [];
    const lines = raw.trim().split("\n").filter(Boolean);

    for (const line of lines) {
      try {
        const entry: NucleiJsonEntry = JSON.parse(line);
        findings.push({
          severity: entry.info?.severity ?? "info",
          title: entry.info?.name ?? entry["template-id"] ?? "Unknown finding",
          detail:
            entry.description ??
            entry.info?.description ??
            `Matched at: ${entry["matched-at"] ?? targetUrl}`,
          templateId: entry["template-id"] ?? "",
        });
      } catch {
        // skip malformed lines
      }
    }

    return { status: "completed", findings };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === "ENOENT") {
      return { status: "not_configured", findings: [] };
    }
    return {
      status: "error",
      findings: [],
      note: `nuclei exited with error: ${error.message}`,
    };
  } finally {
    // Best-effort cleanup — ignore errors if file was never written
    unlink(tmpFile).catch(() => undefined);
  }
}

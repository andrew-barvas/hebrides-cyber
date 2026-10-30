// Nuclei scanner integration.
//
// Uses the nuclei binary (pinned to v3.3.9, by version and SHA-256, in
// .github/workflows/scheduled-scans.yml — there is no worker.Dockerfile).
// When the binary is absent, returns { status: "not_configured" } so the
// worker continues gracefully instead of failing the whole scan job.
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
// default-login/takeover/ssrf/oast) — so a target with zero detectable/
// mappable technology still gets a real, useful nuclei pass, never zero
// effective tags. TECH_TAG_MAP is a best-effort mapping to nuclei's own
// community-maintained tag vocabulary: an entry that doesn't match any real
// template just contributes nothing to -tags' OR-match, exactly as
// harmless as a technology this map doesn't cover at all — never an error,
// never a reason to fall back to the unscoped (slow, noisy) behaviour.
//
// SSRF out-of-band testing (ssrf/oast tags). nuclei's SSRF templates
// (confirmed against the real nuclei-templates repo: 215 tagged "ssrf",
// 601 using the `{{interactsh-url}}` out-of-band placeholder) inject that
// placeholder into a request and match only on `interactsh_protocol` — a
// real callback the target's server made to it, never a response-body
// guess. nuclei resolves `{{interactsh-url}}` against a server it polls
// itself: by default the free public interactsh collaborator pool
// (confirmed via `nuclei -help`: `-iserver` defaults to
// "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me", the same
// ProjectDiscovery-run infrastructure as nuclei/subfinder/httpx
// themselves, already trusted elsewhere in this pipeline) — no server to
// host, no flag needed, nothing new to configure. This isn't a new
// capability so much as un-excluding one: before the Sprint 5 tag
// curation above, nuclei ran unscoped and already fired every OAST
// template; "ssrf"/"oast" simply weren't on the curated allow-list.
// Confirming a real outbound request, never guessing from a response
// body, keeps this a detection, not an attack — no different in kind
// from any other nuclei CVE template already in BASELINE_TAGS.

import { execTool } from "../../lib/execTool";
import { readFile, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";

const execFileAsync = execTool;

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
  // Tags checked against the real nuclei-templates repo (2026-10-19): each has
  // exposed-panel, installer or misconfiguration templates.
  PrestaShop: ["prestashop"],
  OpenCart: ["opencart"],
  TYPO3: ["typo3"],
  Umbraco: ["umbraco"],
  "Craft CMS": ["craftcms"],
  Moodle: ["moodle"],
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
//
// NOT included: "network". nuclei's network-category templates are TCP
// service-protocol templates confirmed real against the repo
// (network/detection/mysql-detect.yaml carries `tags: network,mysql,...`), but
// adding them to the always-on baseline makes nuclei probe service ports on
// every target, and against closed ports each template burns the full
// per-request timeout — a clean run already clocks ~110s, and the extra
// category pushed the step past its 120s budget (nuclei.integration.test.ts).
// Broad network coverage is networkExposure.ts's job (naabu top-1000 + nmap
// -sV, bounded); a scoped nuclei network pass against ONLY the ports naabu
// found is the right follow-up, not a blanket baseline tag that degrades every
// scan's HTTP template run.
const BASELINE_TAGS = ["cve", "exposure", "misconfig", "default-login", "takeover", "ssrf", "oast"];

// NON-INTRUSIVE MODE (the `exposure` profile, scanProfiles.ts). That profile
// is sold as "no test payloads", which BASELINE_TAGS does not meet:
// default-login tries credentials, and ssrf/oast inject a callback URL. So it
// gets its own baseline, every payload-sending tag category is excluded with
// -etags (nuclei applies exclusions after -tags, so a technology tag can't
// pull an excluded template back in), and out-of-band interaction is off (-ni).
// The exclude list is broad on purpose: a template carrying any of these tags
// is skipped even when it would only have detected something.
const NON_INTRUSIVE_TAGS = ["exposure", "misconfig", "takeover", "cve", "panel", "tech"];
const NON_INTRUSIVE_EXCLUDED_TAGS = [
  "intrusive", "dos", "fuzz", "bruteforce", "default-login", "auth-bypass",
  "sqli", "xss", "rce", "lfi", "rfi", "traversal", "ssti", "xxe", "injection",
  "deserialization", "fileupload", "ssrf", "oast",
];

export type NucleiOptions = { nonIntrusive?: boolean };

export function buildTagArgument(detectedTechnologies: string[], options: NucleiOptions = {}): string {
  const mapped = detectedTechnologies.flatMap((name) => TECH_TAG_MAP[name] ?? []);
  const baseline = options.nonIntrusive ? NON_INTRUSIVE_TAGS : BASELINE_TAGS;
  return [...new Set([...baseline, ...mapped])].join(",");
}

export type NucleiFinding = {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
  templateId: string;
  /** From the template's own classification — feeds KEV/EPSS enrichment. */
  cveIds?: string[];
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
    classification?: { "cve-id"?: string[] | string | null };
  };
  "matched-at"?: string;
  description?: string;
};

const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

/**
 * nuclei's -json-export writes ONE JSON array (every result, marshalled on
 * exit); -jsonl output is one object per line. This used to split the array
 * file on newlines, so every real result collapsed into a single "Unknown
 * finding" at info severity. Accepts both shapes.
 */
export function parseNucleiOutput(raw: string, targetUrl: string): NucleiFinding[] {
  const text = raw.trim();
  if (!text) return [];

  let entries: unknown[] = [];
  if (text.startsWith("[")) {
    try {
      const parsed: unknown = JSON.parse(text);
      if (Array.isArray(parsed)) entries = parsed;
    } catch {
      return [];
    }
  } else {
    for (const line of text.split("\n")) {
      try {
        entries.push(JSON.parse(line));
      } catch {
        // skip malformed lines
      }
    }
  }

  const findings: NucleiFinding[] = [];
  for (const item of entries) {
    if (!item || typeof item !== "object") continue;
    const entry = item as NucleiJsonEntry;
    const severity = (entry.info?.severity ?? "").toLowerCase();
    const cve = entry.info?.classification?.["cve-id"];
    const cveIds = [
      ...new Set((Array.isArray(cve) ? cve : cve ? [cve] : []).map((c) => c.toUpperCase()).filter((c) => /^CVE-\d{4}-\d+$/.test(c))),
    ];
    findings.push({
      // nuclei also emits "unknown"; it must never escape as a severity.
      severity: SEVERITIES.has(severity) ? (severity as NucleiFinding["severity"]) : "info",
      title: entry.info?.name ?? entry["template-id"] ?? "Unknown finding",
      detail: entry.description ?? entry.info?.description ?? `Matched at: ${entry["matched-at"] ?? targetUrl}`,
      templateId: entry["template-id"] ?? "",
      ...(cveIds.length > 0 ? { cveIds } : {}),
    });
  }
  return findings;
}

/** A bare hostname (optionally with a port): what nuclei's -iserver takes. */
const INTERACTSH_HOST = /^(?=.{1,253}(?::\d{1,5})?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?$/i;

/**
 * Out-of-band (interactsh) settings for the ssrf/oast templates.
 *
 * By default nuclei uses ProjectDiscovery's public collaborator pool, which
 * sees the callback hostname (and so that a scan of that target ran). Two env
 * switches change that without a code change:
 *   - INTERACTSH_SERVER (+ optional INTERACTSH_TOKEN): use a self-hosted server.
 *     An invalid value is ignored rather than passed to a shell tool, and the
 *     default stays in force.
 *   - DISABLE_OAST=1: no out-of-band at all (-ni); blind-SSRF templates then
 *     can't fire, which loses coverage but sends nothing to any third party.
 */
export function buildInteractshArgs(env: Record<string, string | undefined> = process.env): string[] {
  if (env.DISABLE_OAST === "1") return ["-ni"];
  const server = env.INTERACTSH_SERVER?.trim().replace(/^https?:\/\//i, "").replace(/\/$/, "");
  if (!server || !INTERACTSH_HOST.test(server)) return [];
  const token = env.INTERACTSH_TOKEN?.trim();
  return ["-iserver", server, ...(token ? ["-itoken", token] : [])];
}

export function buildNucleiArgs(
  targetUrl: string,
  tags: string,
  outFile: string,
  env: Record<string, string | undefined> = process.env,
  options: NucleiOptions = {}
): string[] {
  return [
    "-target", targetUrl,
    "-tags", tags,
    "-json-export", outFile,
    "-silent",
    // Per-request timeout in seconds, not the scan's. It used to be 120,
    // so one unresponsive request could outlast the process timeout
    // below, which kills nuclei before it has written any results.
    "-timeout", "10",
    ...(options.nonIntrusive ? ["-etags", NON_INTRUSIVE_EXCLUDED_TAGS.join(","), "-ni"] : buildInteractshArgs(env)),
  ];
}

export async function runNuclei(targetUrl: string, detectedTechnologies: string[] = [], options: NucleiOptions = {}): Promise<NucleiResult> {
  const tmpFile = `/tmp/nuclei-${randomUUID()}.json`;
  const tags = buildTagArgument(detectedTechnologies, options);

  try {
    await execFileAsync(
      "nuclei",
      buildNucleiArgs(targetUrl, tags, tmpFile, process.env, options),
      { timeout: NUCLEI_TIMEOUT_MS }
    );

    let raw: string;
    try {
      raw = await readFile(tmpFile, "utf8");
    } catch {
      // nuclei ran but produced no output file — no findings
      return { status: "completed", findings: [] };
    }

    return { status: "completed", findings: parseNucleiOutput(raw, targetUrl) };
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

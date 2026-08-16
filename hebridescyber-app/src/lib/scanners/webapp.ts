// Web application checks: robots.txt, HTTP methods, error page disclosure,
// WordPress deep scan (if detected), CORS reflected-origin, JS library versions.
// All checks are passive/safe read-only probes — no exploit code.
import { npmPackageNameFor, lookupNpmCveIds, extractCveIdsFromText } from "./osv";

export type WebAppResult =
  | {
      status: "checked";
      robots: RobotsData | null;
      httpMethods: HttpMethodsData;
      errorDisclosure: ErrorDisclosureData;
      wordpress: WordPressData | null;
      corsReflected: CorsReflectedData;
      jsLibraries: JsLibraryFinding[];
    }
  | { status: "error"; note: string };

export type RobotsData = {
  accessible: boolean;
  interestingPaths: string[];
  allDisallowed: string[];
  sitemapUrls: string[];
};

export type HttpMethodsData = {
  allowHeader: string | null;
  dangerousMethods: string[];
};

export type ErrorDisclosureData = {
  probed: boolean;
  disclosesFramework: boolean;
  disclosedStrings: string[];
};

export type WordPressData = {
  xmlRpcEnabled: boolean;
  userEnumerationPossible: boolean;
  debugLogAccessible: boolean;
  readmeAccessible: boolean;
  wpCronAccessible: boolean;
  enumeratedUsers: string[];
};

export type CorsReflectedData = {
  reflectsOrigin: boolean;
  credentialsAllowed: boolean;
  testedOrigin: string;
};

export type JsLibraryFinding = {
  name: string;
  version: string;
  isVulnerable: boolean;
  reason: string;
  // Populated for vulnerable libraries only. Best-effort: a live OSV.dev
  // lookup first, falling back to whatever CVE ids are already named in
  // `reason` if OSV is unreachable or has nothing for this exact version.
  // See src/lib/scanners/osv.ts for why this covers JS libraries specifically
  // and not every risky-software finding in the scanner suite.
  cveIds?: string[];
};

// ── Robots.txt ────────────────────────────────────────────────────────────────

const INTERESTING_PATH_PATTERNS = [
  /admin/i,   /backup/i,    /config/i,   /api/i,      /secret/i,
  /private/i, /internal/i,  /staging/i,  /dev/i,      /test/i,
  /dashboard/i, /upload/i,  /install/i,  /phpMyAdmin/i, /wp-admin/i,
  /\.env/i,   /\.git/i,    /database/i,
];

async function checkRobots(origin: string): Promise<RobotsData | null> {
  try {
    const res = await fetch(`${origin}/robots.txt`, { signal: AbortSignal.timeout(6_000) });
    if (!res.ok) return { accessible: false, interestingPaths: [], allDisallowed: [], sitemapUrls: [] };

    const text = await res.text();
    if (!text.trim() || text.length > 100_000) {
      return { accessible: true, interestingPaths: [], allDisallowed: [], sitemapUrls: [] };
    }

    const lines = text.split(/\r?\n/);
    const disallowed: string[] = [];
    const sitemapUrls: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      const lower = trimmed.toLowerCase();
      if (lower.startsWith("disallow:")) {
        const path = trimmed.slice("disallow:".length).trim();
        if (path) disallowed.push(path);
      }
      if (lower.startsWith("sitemap:")) {
        const url = trimmed.slice("sitemap:".length).trim();
        if (url) sitemapUrls.push(url);
      }
    }

    const interestingPaths = disallowed.filter((p) =>
      INTERESTING_PATH_PATTERNS.some((re) => re.test(p))
    );

    return { accessible: true, interestingPaths, allDisallowed: disallowed, sitemapUrls };
  } catch {
    return null;
  }
}

// ── HTTP dangerous methods ────────────────────────────────────────────────────

const DANGEROUS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"];

async function checkHttpMethods(targetUrl: string): Promise<HttpMethodsData> {
  try {
    const res = await fetch(targetUrl, {
      method: "OPTIONS",
      signal: AbortSignal.timeout(6_000),
    });
    const allow = res.headers.get("allow") ?? res.headers.get("Access-Control-Allow-Methods");
    if (!allow) return { allowHeader: null, dangerousMethods: [] };

    const methods = allow.toUpperCase().split(/[\s,]+/).map((m) => m.trim());
    const dangerous = methods.filter((m) => DANGEROUS.includes(m));
    return { allowHeader: allow, dangerousMethods: dangerous };
  } catch {
    return { allowHeader: null, dangerousMethods: [] };
  }
}

// ── Error page disclosure ─────────────────────────────────────────────────────

const DISCLOSURE_PATTERNS: { re: RegExp; label: string }[] = [
  { re: /at\s+[\w.<>]+\([\w./\\:]+:\d+:\d+\)/,    label: "Node.js stack trace" },
  { re: /File ".*", line \d+, in /,                label: "Python stack trace" },
  { re: /\.(rb|py|php|java|cs):\d+:/,              label: "Source file path in error" },
  { re: /Exception in thread|java\.lang\./,        label: "Java exception" },
  { re: /System\.NullReferenceException|ASP\.NET/, label: "ASP.NET exception" },
  { re: /Fatal error.*PHP|Warning.*PHP\//,         label: "PHP error" },
  { re: /ActiveRecord|ActionController/,           label: "Rails internals" },
  { re: /Whoops!|Illuminate\\|Laravel/,            label: "Laravel debug page" },
  { re: /Django.*Debug|Traceback \(most recent/,   label: "Django debug traceback" },
  { re: /powered by.*express/i,                    label: "Express version disclosure" },
  { re: /nginx\/\d+\.\d+/,                         label: "Nginx version in error page" },
  { re: /Apache\/\d+\.\d+/,                        label: "Apache version in error page" },
];

async function checkErrorDisclosure(origin: string): Promise<ErrorDisclosureData> {
  try {
    // Request a path that almost certainly doesn't exist
    const probe = `${origin}/hc-probe-${Math.random().toString(36).slice(2, 9)}`;
    const res = await fetch(probe, { signal: AbortSignal.timeout(8_000) });

    // Only inspect non-redirect HTML responses
    const ct = res.headers.get("content-type") ?? "";
    if (!ct.includes("text/html") && !ct.includes("text/plain")) {
      return { probed: true, disclosesFramework: false, disclosedStrings: [] };
    }

    const body = await res.text();
    const matched: string[] = [];
    for (const { re, label } of DISCLOSURE_PATTERNS) {
      if (re.test(body)) matched.push(label);
    }

    return {
      probed: true,
      disclosesFramework: matched.length > 0,
      disclosedStrings: matched,
    };
  } catch {
    return { probed: false, disclosesFramework: false, disclosedStrings: [] };
  }
}

// ── WordPress deep scan ───────────────────────────────────────────────────────

async function probePath(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(6_000) });
    return res.ok && res.status === 200;
  } catch {
    return false;
  }
}

async function checkWordPress(origin: string): Promise<WordPressData> {
  const [xmlRpc, usersRes, debugLog, readme, wpCron] = await Promise.all([
    probePath(`${origin}/xmlrpc.php`),
    fetch(`${origin}/wp-json/wp/v2/users`, { signal: AbortSignal.timeout(6_000) }).catch(() => null),
    probePath(`${origin}/wp-content/debug.log`),
    probePath(`${origin}/readme.html`),
    probePath(`${origin}/wp-cron.php`),
  ]);

  let enumeratedUsers: string[] = [];
  let userEnumerationPossible = false;
  if (usersRes?.ok) {
    try {
      const body = (await usersRes.json()) as Array<{ name?: string; slug?: string }>;
      if (Array.isArray(body) && body.length > 0) {
        userEnumerationPossible = true;
        enumeratedUsers = body.map((u) => u.name ?? u.slug ?? "unknown").slice(0, 10);
      }
    } catch { /* ignore */ }
  }

  return {
    xmlRpcEnabled: xmlRpc,
    userEnumerationPossible,
    debugLogAccessible: debugLog,
    readmeAccessible: readme,
    wpCronAccessible: wpCron,
    enumeratedUsers,
  };
}

// ── CORS reflected-origin test ────────────────────────────────────────────────

const TEST_ORIGIN = "https://evil.example.com";

async function checkCorsReflected(targetUrl: string): Promise<CorsReflectedData> {
  try {
    const res = await fetch(targetUrl, {
      headers: { Origin: TEST_ORIGIN },
      signal: AbortSignal.timeout(6_000),
    });
    const acao = res.headers.get("access-control-allow-origin") ?? "";
    const acac = res.headers.get("access-control-allow-credentials") ?? "";

    const reflectsOrigin = acao === TEST_ORIGIN;
    const credentialsAllowed = reflectsOrigin && acac.toLowerCase() === "true";

    return { reflectsOrigin, credentialsAllowed, testedOrigin: TEST_ORIGIN };
  } catch {
    return { reflectsOrigin: false, credentialsAllowed: false, testedOrigin: TEST_ORIGIN };
  }
}

// ── JS library version detection (Retire.js-style) ───────────────────────────

type LibPattern = {
  name: string;
  re: RegExp;
  versionGroup: number;
  // Versions below this major.minor are considered vulnerable
  vulnerableBelow: { major: number; minor?: number };
  reason: string;
};

const LIB_PATTERNS: LibPattern[] = [
  {
    name: "jQuery",
    re: /jquery[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i,
    versionGroup: 1,
    vulnerableBelow: { major: 3, minor: 5 },
    reason: "jQuery < 3.5 has XSS vulnerabilities via jQuery.htmlPrefilter (CVE-2020-11022/23)",
  },
  {
    name: "Moment.js",
    re: /moment(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.min)?\.js/i,
    versionGroup: 1,
    vulnerableBelow: { major: 2, minor: 29 },
    reason: "Moment.js < 2.29.4 has a ReDoS vulnerability (CVE-2022-24785)",
  },
  {
    name: "Lodash",
    re: /lodash(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.min)?\.js/i,
    versionGroup: 1,
    vulnerableBelow: { major: 4, minor: 17 },
    reason: "Lodash < 4.17.21 has prototype pollution vulnerabilities (CVE-2021-23337)",
  },
  {
    name: "Underscore.js",
    re: /underscore(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.min)?\.js/i,
    versionGroup: 1,
    vulnerableBelow: { major: 1, minor: 13 },
    reason: "Underscore.js < 1.13 has template injection vulnerability",
  },
  {
    name: "Bootstrap",
    re: /bootstrap(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.min)?\.(?:js|css)/i,
    versionGroup: 1,
    vulnerableBelow: { major: 4, minor: 3 },
    reason: "Bootstrap < 4.3.1 has XSS vulnerability in data-template attribute (CVE-2019-8331)",
  },
  {
    name: "AngularJS",
    re: /angular(?:js)?[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i,
    versionGroup: 1,
    vulnerableBelow: { major: 1, minor: 8 },
    reason: "AngularJS 1.x (all versions) is end-of-life since 2022 with no security patches",
  },
  {
    name: "Prototype.js",
    re: /prototype(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.min)?\.js/i,
    versionGroup: 1,
    vulnerableBelow: { major: 2 },
    reason: "Prototype.js is abandoned — no security patches since 2010",
  },
];

function isVulnerable(version: string, limit: { major: number; minor?: number }): boolean {
  const [maj, min] = version.split(".").map(Number);
  if (maj < limit.major) return true;
  if (maj === limit.major && limit.minor !== undefined && !isNaN(min) && min < limit.minor) return true;
  return false;
}

async function checkJsLibraries(targetUrl: string): Promise<JsLibraryFinding[]> {
  try {
    const res = await fetch(targetUrl, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return [];
    const html = await res.text();

    const findings: JsLibraryFinding[] = [];
    const seen = new Set<string>();

    for (const pattern of LIB_PATTERNS) {
      const m = html.match(pattern.re);
      if (!m || seen.has(pattern.name)) continue;
      seen.add(pattern.name);

      const version = m[pattern.versionGroup] ?? null;
      if (!version) {
        // Library detected but version unknown — report as info only
        findings.push({
          name: pattern.name,
          version: "unknown",
          isVulnerable: false,
          reason: `${pattern.name} detected in page HTML (version could not be determined)`,
        });
        continue;
      }

      const vuln = isVulnerable(version, pattern.vulnerableBelow);
      findings.push({
        name: pattern.name,
        version,
        isVulnerable: vuln,
        reason: vuln ? pattern.reason : `${pattern.name} ${version} appears to be a current version`,
      });
    }

    // CVE enrichment, in parallel, only for libraries actually flagged —
    // no point spending a network round-trip confirming a current version
    // has no known issues.
    await Promise.all(
      findings.map(async (finding) => {
        if (!finding.isVulnerable) return;

        const npmName = npmPackageNameFor(finding.name);
        const liveIds = npmName ? await lookupNpmCveIds(npmName, finding.version) : [];
        finding.cveIds = liveIds.length > 0 ? liveIds : extractCveIdsFromText(finding.reason);
      })
    );

    return findings;
  } catch {
    return [];
  }
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function checkWebApp(
  targetUrl: string,
  isWordPress: boolean
): Promise<WebAppResult> {
  try {
    const origin = new URL(targetUrl).origin;

    const [robots, httpMethods, errorDisclosure, corsReflected, jsLibraries] =
      await Promise.all([
        checkRobots(origin),
        checkHttpMethods(targetUrl),
        checkErrorDisclosure(origin),
        checkCorsReflected(targetUrl),
        checkJsLibraries(targetUrl),
      ]);

    const wordpress = isWordPress ? await checkWordPress(origin) : null;

    return {
      status: "checked",
      robots,
      httpMethods,
      errorDisclosure,
      wordpress,
      corsReflected,
      jsLibraries,
    };
  } catch (err) {
    return { status: "error", note: `Web app check failed: ${(err as Error).message}` };
  }
}

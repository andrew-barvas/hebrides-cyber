// Web application checks: robots.txt, HTTP methods, error page disclosure,
// WordPress deep scan (if detected), CORS reflected-origin, JS library
// versions, Subresource Integrity on cross-origin scripts/stylesheets.
// All checks are passive/safe read-only probes — no exploit code.
import { npmPackageNameFor, lookupNpmCveIds, extractCveIdsFromText } from "./osv";
import { type Baseline, normaliseBody, fetchBaseline, matchesBaselineHeaders, isCatchAllBody } from "./httpProbe";

export type WebAppResult =
  | {
      status: "checked";
      robots: RobotsData | null;
      httpMethods: HttpMethodsData;
      errorDisclosure: ErrorDisclosureData;
      wordpress: WordPressData | null;
      joomla: JoomlaData | null;
      drupal: DrupalData | null;
      corsReflected: CorsReflectedData;
      jsLibraries: JsLibraryFinding[];
      unprotectedResources: UnprotectedResource[];
    }
  | { status: "error"; note: string };

export type CmsFlags = { isWordPress: boolean; isJoomla: boolean; isDrupal: boolean };

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
  plugins: DetectedPlugin[];
};

// A plugin name + version pair read from the plugin's own public readme.txt.
// See the "WordPress plugin version detection" section below for how this is
// produced and why no cveIds field exists here (OSV.dev has no WordPress
// plugin ecosystem — see src/lib/scanners/osv.ts's ecosystem comment).
export type DetectedPlugin = {
  slug: string;
  name: string;
  version: string;
};

export type JoomlaData = {
  // From the administrator manifest — null if unreadable or version absent.
  version: string | null;
  // htaccess.txt / web.config.txt: shipped by Joomla core, meant to be
  // renamed after install. Left in place, they're a signal the install was
  // never hardened — not a vulnerability in themselves.
  installFilesPresent: boolean;
};

export type DrupalData = {
  // From CHANGELOG.txt — null if unreadable or version absent.
  version: string | null;
  updatePhpAccessible: boolean;
  jsonApiExposed: boolean;
  // uid 1 is Drupal's built-in superuser account — a public profile page
  // there confirms the admin account exists and is reachable by URL.
  uid1ProfileAccessible: boolean;
};

export type CorsReflectedData = {
  reflectsOrigin: boolean;
  credentialsAllowed: boolean;
  testedOrigin: string;
};

// A cross-origin <script> or <link rel="stylesheet"> the page loads without
// a Subresource Integrity hash. Same-origin resources are never checked —
// SRI protects against a *third party* being compromised or MITM'd, not
// against the site's own origin, so flagging a same-origin asset would be
// noise with no real protection story attached.
export type UnprotectedResource = { kind: "script" | "stylesheet"; url: string };

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
    // Allow only. Access-Control-Allow-Methods is a CORS preflight answer —
    // which methods a cross-origin caller may *ask* to use — and frameworks
    // send a permissive default list on every OPTIONS. It is not evidence the
    // server accepts PUT/DELETE, so it must not produce this finding.
    const allow = res.headers.get("allow");
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
  // These match the framework's own error page, not a page that merely names
  // the framework: "Whoops!" is common 404 copy, and an agency's 404 page can
  // list "ASP.NET" or "Laravel" among its services.
  { re: /System\.NullReferenceException|ASP\.NET Version:|Server Error in '\/' Application/, label: "ASP.NET exception" },
  { re: /Fatal error.*PHP|Warning.*PHP\//,         label: "PHP error" },
  { re: /ActiveRecord::|ActionController::/,       label: "Rails internals" },
  { re: /Whoops! There was an error|Illuminate\\[A-Z]|vendor\/laravel\/framework/, label: "Laravel debug page" },
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
  // Baseline is shared by the plugin readme.txt probes below — see the
  // "WordPress plugin version detection" section for why it's needed.
  const [xmlRpc, usersRes, debugLog, readme, wpCron, baseline] = await Promise.all([
    probePath(`${origin}/xmlrpc.php`),
    fetch(`${origin}/wp-json/wp/v2/users`, { signal: AbortSignal.timeout(6_000) }).catch(() => null),
    probePath(`${origin}/wp-content/debug.log`),
    probePath(`${origin}/readme.html`),
    probePath(`${origin}/wp-cron.php`),
    fetchBaseline(origin),
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

  const plugins = await detectPlugins(origin, baseline);

  return {
    xmlRpcEnabled: xmlRpc,
    userEnumerationPossible,
    debugLogAccessible: debugLog,
    readmeAccessible: readme,
    wpCronAccessible: wpCron,
    enumeratedUsers,
    plugins,
  };
}

// ── WordPress plugin version detection ──────────────────────────────────────
// Every plugin hosted on the official wordpress.org repository ships a public
// /wp-content/plugins/<slug>/readme.txt with a "Stable tag: X.Y.Z" line —
// wp.org's own directory listing reads that same line to know what version to
// serve, so it's the plugin author's own declared version, not a guess.
//
// Deliberately NOT a brute force of the thousands of slugs on wp.org: this
// list is capped to plugins that are both genuinely common and have a
// meaningful history of CVEs, so the check stays low-noise and low-volume.
// If a plugin isn't installed, its readme.txt 404s (or gets caught by the
// baseline/catch-all check below) — nothing is reported either way.
type PluginCandidate = { slug: string; name: string };

const PLUGIN_CANDIDATES: PluginCandidate[] = [
  { slug: "wordpress-seo", name: "Yoast SEO" },
  { slug: "elementor", name: "Elementor" },
  { slug: "woocommerce", name: "WooCommerce" },
  { slug: "contact-form-7", name: "Contact Form 7" },
  { slug: "jetpack", name: "Jetpack" },
  { slug: "wpforms-lite", name: "WPForms" },
  { slug: "all-in-one-seo-pack", name: "All in One SEO" },
  { slug: "updraftplus", name: "UpdraftPlus" },
  { slug: "wordfence", name: "Wordfence Security" },
  { slug: "akismet", name: "Akismet" },
  { slug: "really-simple-ssl", name: "Really Simple SSL" },
  { slug: "advanced-custom-fields", name: "Advanced Custom Fields" },
  { slug: "litespeed-cache", name: "LiteSpeed Cache" },
  { slug: "w3-total-cache", name: "W3 Total Cache" },
  { slug: "wp-super-cache", name: "WP Super Cache" },
  { slug: "wp-smushit", name: "Smush" },
  { slug: "redirection", name: "Redirection" },
  { slug: "better-wp-security", name: "iThemes/Solid Security" },
  { slug: "ninja-forms", name: "Ninja Forms" },
  { slug: "google-analytics-for-wordpress", name: "MonsterInsights" },
];

// Run readme.txt probes in small concurrent batches — bounds both total
// request volume (capped candidate list) and in-flight concurrency (this),
// so 20 candidates neither hit the target sequentially one-by-one (slow) nor
// all at once (bursty/abusive).
const PLUGIN_PROBE_CONCURRENCY = 5;

const STABLE_TAG_RE = /Stable tag:\s*([\w.\-]+)/i;

async function probePlugin(origin: string, candidate: PluginCandidate, baseline: Baseline): Promise<DetectedPlugin | null> {
  const path = `/wp-content/plugins/${candidate.slug}/readme.txt`;
  try {
    const res = await fetch(origin + path, { redirect: "manual", signal: AbortSignal.timeout(6_000) });
    if (res.status !== 200) return null;

    // Belt-and-suspenders: same document as the site root for every path.
    if (matchesBaselineHeaders(baseline, res)) return null;

    const text = await res.text().catch(() => "");
    const masked = normaliseBody(text, path);

    // Same document as a URL we know doesn't exist — this "plugin" isn't real.
    if (isCatchAllBody(baseline, masked)) return null;

    // A genuine wp.org readme.txt always declares a stable tag. A catch-all
    // shell (or an unrelated 200) will not — this is the decisive check, not
    // just a version-extraction convenience.
    const m = text.match(STABLE_TAG_RE);
    if (!m) return null;

    return { slug: candidate.slug, name: candidate.name, version: m[1] };
  } catch {
    return null; // Network errors are not findings.
  }
}

async function detectPlugins(origin: string, baseline: Baseline): Promise<DetectedPlugin[]> {
  const found: DetectedPlugin[] = [];
  for (let i = 0; i < PLUGIN_CANDIDATES.length; i += PLUGIN_PROBE_CONCURRENCY) {
    const batch = PLUGIN_CANDIDATES.slice(i, i + PLUGIN_PROBE_CONCURRENCY);
    const results = await Promise.allSettled(batch.map((c) => probePlugin(origin, c, baseline)));
    for (const r of results) {
      if (r.status === "fulfilled" && r.value) found.push(r.value);
    }
  }
  return found;
}

// ── Joomla deep scan ───────────────────────────────────────────────────────────

async function checkJoomla(origin: string): Promise<JoomlaData> {
  const [manifestRes, htaccessTxt, webConfigTxt] = await Promise.all([
    fetch(`${origin}/administrator/manifests/files/joomla.xml`, { signal: AbortSignal.timeout(6_000) }).catch(() => null),
    probePath(`${origin}/htaccess.txt`),
    probePath(`${origin}/web.config.txt`),
  ]);

  let version: string | null = null;
  if (manifestRes?.ok) {
    const body = await manifestRes.text().catch(() => "");
    const m = body.match(/<version>([\d.]+)<\/version>/i);
    if (m) version = m[1];
  }

  return { version, installFilesPresent: htaccessTxt || webConfigTxt };
}

// ── Drupal deep scan ────────────────────────────────────────────────────────────

async function checkDrupal(origin: string): Promise<DrupalData> {
  const [changelogRoot, changelogCore, updatePhp, jsonApiRes, uid1Res] = await Promise.all([
    fetch(`${origin}/CHANGELOG.txt`, { signal: AbortSignal.timeout(6_000) }).catch(() => null),
    fetch(`${origin}/core/CHANGELOG.txt`, { signal: AbortSignal.timeout(6_000) }).catch(() => null),
    probePath(`${origin}/update.php`),
    fetch(`${origin}/jsonapi`, { signal: AbortSignal.timeout(6_000) }).catch(() => null),
    fetch(`${origin}/user/1`, { redirect: "manual", signal: AbortSignal.timeout(6_000) }).catch(() => null),
  ]);

  let version: string | null = null;
  for (const res of [changelogRoot, changelogCore]) {
    if (!res?.ok) continue;
    const body = await res.text().catch(() => "");
    const m = body.match(/Drupal (\d+\.\d+(?:\.\d+)?),/i);
    if (m) {
      version = m[1];
      break;
    }
  }

  const jsonApiExposed = Boolean(
    jsonApiRes?.ok && (jsonApiRes.headers.get("content-type") ?? "").includes("vnd.api+json")
  );

  return {
    version,
    updatePhpAccessible: updatePhp,
    jsonApiExposed,
    uid1ProfileAccessible: uid1Res?.status === 200,
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
  // The library's own filename, sometimes carrying a version ("jquery-3.4.1.min.js").
  re: RegExp;
  // Its package directory on the public CDNs, where the version lives in the
  // path, not the filename ("cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js").
  // That is how most sites load these libraries, and `re` alone saw only an
  // unversioned "jquery.min.js" there — or, for jQuery, nothing at all.
  cdnPackages: string[];
  // First release with the fix, compared to the patch level. A major.minor
  // threshold passed Lodash 4.17.15 and Moment 2.29.1 as current, though both
  // are inside the very CVE ranges `reason` names.
  vulnerableBelow: string;
  reason: string;
};

const LIB_PATTERNS: LibPattern[] = [
  {
    name: "jQuery",
    re: /jquery[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i,
    cdnPackages: ["jquery"],
    vulnerableBelow: "3.5.0",
    reason: "jQuery < 3.5 has XSS vulnerabilities via jQuery.htmlPrefilter (CVE-2020-11022/23)",
  },
  {
    name: "Moment.js",
    re: /moment(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.min)?\.js/i,
    cdnPackages: ["moment.js", "moment"],
    vulnerableBelow: "2.29.4",
    reason: "Moment.js < 2.29.4 has a ReDoS vulnerability (CVE-2022-24785)",
  },
  {
    name: "Lodash",
    re: /lodash(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.min)?\.js/i,
    cdnPackages: ["lodash.js", "lodash"],
    vulnerableBelow: "4.17.21",
    reason: "Lodash < 4.17.21 has prototype pollution vulnerabilities (CVE-2021-23337)",
  },
  {
    name: "Underscore.js",
    re: /underscore(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.min)?\.js/i,
    cdnPackages: ["underscore.js", "underscore"],
    vulnerableBelow: "1.13.0",
    reason: "Underscore.js < 1.13 has template injection vulnerability",
  },
  {
    name: "Bootstrap",
    re: /bootstrap(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.min)?\.(?:js|css)/i,
    cdnPackages: ["twitter-bootstrap", "bootstrap"],
    vulnerableBelow: "4.3.1",
    reason: "Bootstrap < 4.3.1 has XSS vulnerability in data-template attribute (CVE-2019-8331)",
  },
  {
    // npm "angular" is AngularJS; Angular 2+ is published as @angular/*, which
    // the CDN pattern can't match.
    name: "AngularJS",
    re: /angular(?:js)?[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i,
    cdnPackages: ["angular.js", "angular"],
    vulnerableBelow: "2.0.0",
    reason: "AngularJS 1.x (all versions) is end-of-life since 2022 with no security patches",
  },
  {
    name: "Prototype.js",
    re: /prototype(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.min)?\.js/i,
    cdnPackages: ["prototype"],
    vulnerableBelow: "2.0.0",
    reason: "Prototype.js is abandoned — no security patches since 2010",
  },
];

const CDN_PACKAGE_RE = /(?:cdnjs\.cloudflare\.com\/ajax\/libs\/|cdn\.jsdelivr\.net\/npm\/|unpkg\.com\/)([\w.-]+)[@/](\d+\.\d+(?:\.\d+)?)\//gi;

function cdnVersion(html: string, packages: string[]): string | null {
  for (const m of html.matchAll(CDN_PACKAGE_RE)) {
    if (packages.includes(m[1].toLowerCase())) return m[2];
  }
  return null;
}

export function isVersionBelow(version: string, fixedIn: string): boolean {
  const a = version.split(".").map(Number);
  const b = fixedIn.split(".").map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (Number.isNaN(x) || Number.isNaN(y)) return false;
    if (x !== y) return x < y;
  }
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
      const fromCdn = cdnVersion(html, pattern.cdnPackages);
      const m = fromCdn ? null : html.match(pattern.re);
      if ((!fromCdn && !m) || seen.has(pattern.name)) continue;
      seen.add(pattern.name);

      const version = fromCdn ?? m?.[1] ?? null;
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

      const vuln = isVersionBelow(version, pattern.vulnerableBelow);
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

// ── Subresource Integrity ─────────────────────────────────────────────────────
//
// A cross-origin <script>/<link rel="stylesheet"> with no integrity="..."
// hash means the page trusts that third party completely — if the CDN is
// compromised, has its DNS hijacked, or is MITM'd, it can serve arbitrary
// JS/CSS to every visitor with no way for the browser to notice. This only
// checks whether the attribute is *present*, never whether the hash is
// correct — validating that would mean fetching and hashing every external
// resource, a meaningfully heavier check than reading one HTML attribute,
// and out of scope here. Presence alone is still real, evidenced signal:
// a resource with no integrity attribute at all has zero SRI protection
// regardless of what a correctness check might additionally find.
//
// Same regex-over-raw-HTML approach as checkJsLibraries below, not a real
// HTML parser — consistent with the rest of this file, and sufficient for
// pulling src/href + integrity out of a tag without needing a DOM.

const SCRIPT_TAG_RE = /<script\b[^>]*>/gi;
const LINK_STYLESHEET_RE = /<link\b[^>]*rel=["']stylesheet["'][^>]*>/gi;
// Also matches <link ... href="..." rel="stylesheet" ...> where href comes
// before rel — LINK_STYLESHEET_RE above only requires rel=stylesheet to
// appear somewhere in the tag, order-independent.
const SRC_ATTR_RE = /\bsrc=["']([^"']+)["']/i;
const HREF_ATTR_RE = /\bhref=["']([^"']+)["']/i;
const INTEGRITY_ATTR_RE = /\bintegrity=["'][^"']+["']/i;

// Cap matches how every other module in this codebase bounds worst-case
// output — a page with 200 third-party script tags must not produce 200
// individual findings; see remediationText.ts's sriRemediation for the
// rolled-up wording used once this cap is hit.
const MAX_UNPROTECTED_RESOURCES = 15;

export function isCrossOrigin(rawUrl: string, pageOrigin: string): boolean {
  try {
    const resolved = new URL(rawUrl, pageOrigin);
    return resolved.origin !== pageOrigin;
  } catch {
    return false; // unparseable (e.g. a data: URI) — not a cross-origin asset to flag
  }
}

export type ScriptTag = { src: string; hasIntegrity: boolean };

/**
 * Every `<script src>` tag in raw HTML, in document order: the src exactly as
 * written (unresolved) and whether the tag carries an integrity attribute.
 * Inline scripts are skipped. Shared with scriptInventory.ts, which lists
 * every third-party script origin rather than only the unprotected ones.
 */
export function extractScriptTags(html: string): ScriptTag[] {
  const tags: ScriptTag[] = [];
  for (const tag of html.match(SCRIPT_TAG_RE) ?? []) {
    const src = tag.match(SRC_ATTR_RE)?.[1];
    if (src) tags.push({ src, hasIntegrity: INTEGRITY_ATTR_RE.test(tag) });
  }
  return tags;
}

async function checkSubresourceIntegrity(targetUrl: string): Promise<UnprotectedResource[]> {
  try {
    const res = await fetch(targetUrl, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return [];
    const html = await res.text();
    const pageOrigin = new URL(targetUrl).origin;

    const unprotected: UnprotectedResource[] = [];

    for (const { src, hasIntegrity } of extractScriptTags(html)) {
      if (unprotected.length >= MAX_UNPROTECTED_RESOURCES) break;
      if (!isCrossOrigin(src, pageOrigin)) continue; // same-origin script — not this check's concern
      if (!hasIntegrity) unprotected.push({ kind: "script", url: src });
    }

    for (const tag of html.match(LINK_STYLESHEET_RE) ?? []) {
      if (unprotected.length >= MAX_UNPROTECTED_RESOURCES) break;
      const href = tag.match(HREF_ATTR_RE)?.[1];
      if (!href || !isCrossOrigin(href, pageOrigin)) continue;
      if (!INTEGRITY_ATTR_RE.test(tag)) unprotected.push({ kind: "stylesheet", url: href });
    }

    return unprotected;
  } catch {
    return [];
  }
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function checkWebApp(targetUrl: string, cms: CmsFlags): Promise<WebAppResult> {
  try {
    const origin = new URL(targetUrl).origin;

    const [robots, httpMethods, errorDisclosure, corsReflected, jsLibraries, unprotectedResources] =
      await Promise.all([
        checkRobots(origin),
        checkHttpMethods(targetUrl),
        checkErrorDisclosure(origin),
        checkCorsReflected(targetUrl),
        checkJsLibraries(targetUrl),
        checkSubresourceIntegrity(targetUrl),
      ]);

    const [wordpress, joomla, drupal] = await Promise.all([
      cms.isWordPress ? checkWordPress(origin) : Promise.resolve(null),
      cms.isJoomla ? checkJoomla(origin) : Promise.resolve(null),
      cms.isDrupal ? checkDrupal(origin) : Promise.resolve(null),
    ]);

    return {
      status: "checked",
      robots,
      httpMethods,
      errorDisclosure,
      wordpress,
      joomla,
      drupal,
      corsReflected,
      jsLibraries,
      unprotectedResources,
    };
  } catch (err) {
    return { status: "error", note: `Web app check failed: ${(err as Error).message}` };
  }
}

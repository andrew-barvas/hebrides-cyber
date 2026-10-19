// Technology fingerprinting — Wappalyzer-style passive detection from HTTP
// response headers and page HTML. No external tools or API keys required.
// Detects 40+ common frameworks, CMSes, servers, CDNs, and third-party
// services and maps known versions to CVE advisories where relevant.

export type FingerprintResult =
  | { status: "checked"; technologies: DetectedTech[]; riskySoftware: RiskyTech[] }
  | { status: "error"; note: string };

export type DetectedTech = {
  name: string;
  category: string;
  version: string | null;
  confidence: "high" | "medium" | "low";
  source: "header" | "html" | "both";
  /**
   * Linux distribution named in the same header as the version
   * ("Apache/2.4.41 (Ubuntu)", "PHP/7.4.3-4ubuntu2.19"). Distributions
   * backport security fixes, so endOfLife.ts treats upstream EOL for these
   * as "check with your vendor", not "unpatched".
   */
  packagedBy?: string;
};

const DISTRO_MARKERS: Array<[RegExp, string]> = [
  [/ubuntu/i, "Ubuntu"],
  [/debian|[+~]deb\d+u\d+/i, "Debian"],
  [/red ?hat|\brhel\b|\.el\d+/i, "Red Hat"],
  [/centos/i, "CentOS"],
  [/almalinux/i, "AlmaLinux"],
  [/rocky/i, "Rocky Linux"],
  [/fedora/i, "Fedora"],
  [/amzn|amazon linux/i, "Amazon Linux"],
  [/suse/i, "SUSE"],
];

export function distroFromHeader(value: string): string | null {
  return DISTRO_MARKERS.find(([re]) => re.test(value))?.[1] ?? null;
}

export type RiskyTech = {
  name: string;
  version: string;
  reason: string;
};

// ---- Detection patterns ---------------------------------------------------

type Pattern = {
  name: string;
  category: string;
  // Header-based detection: { headerName: regex }
  headers?: Record<string, RegExp>;
  // HTML-based detection: regex against the page source
  html?: RegExp;
  // Version capture group index in the matching regex
  versionGroup?: number;
};

const PATTERNS: Pattern[] = [
  // ---- Web servers ----------------------------------------------------------
  { name: "Apache", category: "Web server", headers: { server: /Apache(?:\/(\d+\.\d+[\.\d]*))?/i }, versionGroup: 1 },
  { name: "Nginx", category: "Web server", headers: { server: /nginx(?:\/(\d+\.\d+[\.\d]*))?/i }, versionGroup: 1 },
  { name: "IIS", category: "Web server", headers: { server: /Microsoft-IIS(?:\/(\d+\.\d+))?/i }, versionGroup: 1 },
  { name: "LiteSpeed", category: "Web server", headers: { server: /LiteSpeed/i } },
  { name: "Caddy", category: "Web server", headers: { server: /Caddy/i } },

  // ---- Languages / runtimes ------------------------------------------------
  { name: "PHP", category: "Language", headers: { "x-powered-by": /PHP(?:\/(\d+\.\d+[\.\d]*))?/i }, versionGroup: 1 },
  { name: "ASP.NET", category: "Framework", headers: { "x-powered-by": /ASP\.NET/i, "x-aspnet-version": /.+/ } },
  { name: "Node.js", category: "Runtime", headers: { "x-powered-by": /Express|Node/i } },

  // ---- CDN / hosting -------------------------------------------------------
  { name: "Cloudflare", category: "CDN", headers: { "cf-ray": /.+/, server: /cloudflare/i } },
  { name: "Vercel", category: "Hosting", headers: { "x-vercel-id": /.+/, server: /Vercel/i } },
  { name: "AWS CloudFront", category: "CDN", headers: { "x-amz-cf-id": /.+/, "x-amz-cf-pop": /.+/ } },
  { name: "Fastly", category: "CDN", headers: { "x-fastly-request-id": /.+/ } },
  { name: "Akamai", category: "CDN", headers: { "x-akamai-transformed": /.+/ } },
  { name: "Azure CDN", category: "CDN", headers: { "x-msedge-ref": /.+/, "x-azure-ref": /.+/ } },
  // Azure App Service / Static Web Apps' managed Functions front end sets
  // ARR session-affinity cookies; it sends no x-azure-ref on SWA, so this is
  // the signal that TLS is terminated by Azure's platform (see deepTls.ts).
  { name: "Azure App Service", category: "Hosting", headers: { "set-cookie": /\bARRAffinity=/i } },

  // ---- Frameworks (header-detected) -----------------------------------------
  { name: "Next.js", category: "Framework", headers: { "x-nextjs-cache": /.+/, "x-powered-by": /Next\.js/i } },
  { name: "Nuxt.js", category: "Framework", headers: { "x-powered-by": /Nuxt/i } },
  { name: "Ruby on Rails", category: "Framework", headers: { "x-powered-by": /Phusion Passenger/i } },
  // Header rules match on ANY one header, so this used to include
  // X-Frame-Options: SAMEORIGIN and X-Content-Type-Options: nosniff — generic
  // security headers every well-configured site sends, which labelled all of
  // them "Django" (including our own Next.js site). The CSRF form field name
  // is Django's own.
  { name: "Django", category: "Framework", headers: { server: /Django|Gunicorn|uWSGI/i }, html: /name=["']csrfmiddlewaretoken["']/i },
  { name: "Laravel", category: "Framework", html: /laravel_session|_token.*csrf/i },

  // ---- CMS -----------------------------------------------------------------
  { name: "WordPress", category: "CMS", html: /wp-content|wp-includes|generator.*WordPress (\d+\.\d+)/i, versionGroup: 1 },
  { name: "Drupal", category: "CMS", html: /Drupal(?:\.settings|\/(\d+))/i, versionGroup: 1, headers: { "x-generator": /Drupal (\d+)/i } },
  { name: "Joomla", category: "CMS", html: /\/media\/jui\/|Joomla! - Open Source Content Management/i },
  { name: "Ghost", category: "CMS", html: /ghost-root|content="Ghost (\d+\.\d+)/i, versionGroup: 1 },
  { name: "Shopify", category: "E-commerce", html: /cdn\.shopify\.com|Shopify\.theme/i, headers: { "x-shopify-stage": /.+/ } },
  { name: "Magento", category: "E-commerce", html: /Mage\.(?:Cookies|Config)|\/skin\/frontend\//i },
  // More CMS and shop platforms. These are passive, markup-only signals, and
  // most of these platforms don't publish their version on a public page, so a
  // detection usually has no version and the CVE and end-of-life checks stay
  // silent about it (a name alone is never evidence of a vulnerability). The
  // nuclei tag scoping, asset inventory and tech inventory still benefit.
  // PrestaShop 1.6 sends a generator meta tag; 1.7+ defines a global
  // `prestashop` object and serves modules/ps_* assets.
  { name: "PrestaShop", category: "E-commerce", html: /(?:var|window\.)\s*prestashop\s*=\s*\{|<meta[^>]+name=["']generator["'][^>]+content=["']PrestaShop|\/modules\/ps_[a-z0-9_]+\//i },
  { name: "OpenCart", category: "E-commerce", html: /["'(=/]catalog\/view\/(?:theme|javascript)\//i },
  // Old TYPO3 (up to 6.x) put the version in the tag: content="TYPO3 6.2 CMS".
  { name: "TYPO3", category: "CMS", html: /\/typo3(?:temp|conf)\/|<meta[^>]+name=["']generator["'][^>]+content=["']TYPO3/i },
  { name: "TYPO3", category: "CMS", html: /content=["']TYPO3 (\d+(?:\.\d+)*) CMS/i, versionGroup: 1 },
  // Umbraco 7/8 sent X-Umbraco-Version by default; the back office lives under /umbraco/.
  { name: "Umbraco", category: "CMS", html: /\/umbraco\/(?:lib|backoffice|assets|api|surface)\//i, headers: { "x-umbraco-version": /(\d+\.\d+[\.\d]*)/ }, versionGroup: 1 },
  // Craft sends X-Powered-By: Craft CMS unless disabled; control-panel assets are under /cpresources/.
  { name: "Craft CMS", category: "CMS", html: /\/cpresources\//i, headers: { "x-powered-by": /Craft CMS/i } },
  { name: "Moodle", category: "LMS", html: /M\.cfg\s*=\s*\{|<meta[^>]+name=["']keywords["'][^>]+content=["']moodle|\/(?:theme\/(?:styles|image|yui_combo)|lib\/javascript)\.php\//i },
  { name: "Wix", category: "Hosting", html: /wix\.com\/|wixstatic\.com/i },
  { name: "Squarespace", category: "Hosting", html: /squarespace\.com\/|Static\.SQUARESPACE_URLS/i },
  { name: "Webflow", category: "Hosting", html: /webflow\.com\/|data-wf-page/i },

  // ---- JavaScript frameworks (HTML-detected) --------------------------------
  { name: "React", category: "JS Framework", html: /__reactFiber|react-dom|data-reactroot/i },
  { name: "Vue.js", category: "JS Framework", html: /data-v-\w+|vue(?:\.min)?\.js/i },
  { name: "Angular", category: "JS Framework", html: /ng-version=["'](\d+\.\d+)/i, versionGroup: 1 },
  { name: "Svelte", category: "JS Framework", html: /svelte(?:-\d+)?\.(js|css)|__svelte/i },
  { name: "jQuery", category: "JS Library", html: /jquery[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i, versionGroup: 1 },
  { name: "Bootstrap", category: "CSS Framework", html: /bootstrap(?:-(\d+\.\d+\.\d+))?(?:\.min)?\.(js|css)/i, versionGroup: 1 },
  { name: "Tailwind CSS", category: "CSS Framework", html: /tailwind(?:css)?(?:\.min)?\.css|class="[^"]*(?:text-|bg-|flex|grid)/i },

  // ---- Analytics / tracking ------------------------------------------------
  { name: "Google Analytics 4", category: "Analytics", html: /gtag\('config',\s*'G-/i },
  { name: "Google Analytics UA", category: "Analytics", html: /ga\('create',\s*'UA-/i },
  { name: "Google Tag Manager", category: "Tag manager", html: /googletagmanager\.com\/gtm\.js\?id=GTM-/i },
  { name: "Facebook Pixel", category: "Analytics", html: /connect\.facebook\.net\/.*\/fbevents\.js/i },
  { name: "Hotjar", category: "Analytics", html: /static\.hotjar\.com|hjid:/i },
  { name: "Mixpanel", category: "Analytics", html: /cdn\.mxpnl\.com|mixpanel\.init/i },

  // ---- Security services ---------------------------------------------------
  { name: "reCAPTCHA", category: "Bot protection", html: /google\.com\/recaptcha|recaptcha\.enterprise/i },
  { name: "hCaptcha", category: "Bot protection", html: /hcaptcha\.com\/1\/api\.js/i },
  { name: "Turnstile (Cloudflare)", category: "Bot protection", html: /challenges\.cloudflare\.com\/turnstile/i },
  { name: "Imperva", category: "WAF", headers: { "x-cdn": /Imperva/i, "x-iinfo": /.+/ } },
  { name: "Sucuri WAF", category: "WAF", headers: { "x-sucuri-id": /.+/, "x-sucuri-cache": /.+/ } },

  // ---- Payment processors --------------------------------------------------
  { name: "Stripe", category: "Payments", html: /js\.stripe\.com/i },
  { name: "PayPal", category: "Payments", html: /paypal\.com\/sdk\/js/i },
  { name: "Square", category: "Payments", html: /squareup\.com\/js/i },
];

// Known-outdated versions that carry significant CVEs.
type KnownRisky = { name: string; maxSafeMajor: number; reason: string };
const KNOWN_RISKY: KnownRisky[] = [
  { name: "jQuery", maxSafeMajor: 3, reason: "jQuery < 3.x has multiple XSS and prototype-pollution CVEs" },
  { name: "Bootstrap", maxSafeMajor: 5, reason: "Bootstrap < 5.x has XSS vulnerabilities in data attribute handlers" },
  { name: "WordPress", maxSafeMajor: 6, reason: "WordPress < 6.x is out of active security support" },
  { name: "Angular", maxSafeMajor: 15, reason: "Angular < 15 is beyond LTS and has unpatched CVEs" },
  { name: "PHP", maxSafeMajor: 8, reason: "PHP < 8.0 is end-of-life with no security patches" },
  { name: "Apache", maxSafeMajor: 2, reason: "Apache 1.x is end-of-life" },
];

// Flat list of technology names this module can actually fingerprint — kept
// derived from PATTERNS (not hand-duplicated) so it can never drift out of
// sync with real detection capability. Consumed by src/lib/newsletter.ts to
// correlate external vulnerability feeds (e.g. CISA's KEV catalog) against
// what this product can honestly claim to detect, so the newsletter never
// overclaims coverage it doesn't have.
export const DETECTABLE_TECHNOLOGIES: string[] = [...new Set(PATTERNS.map((p) => p.name))];

export type CmsType = "wordpress" | "joomla" | "drupal" | "magento" | "shopify" | "ghost" | "prestashop" | "opencart" | "typo3" | "umbraco" | "craft" | "moodle";

// Single-value "what CMS is this" derivation, used to route CMS-specific
// scanning (targeted scanners, scan profiles) rather than each consumer
// re-deriving its own isWordPress/isJoomla/... flags from raw DetectedTech
// names. Matches by name, not category — Magento's/Shopify's PATTERNS
// category above is "E-commerce", not "CMS", so filtering by category here
// would silently drop them. Precedence (WordPress > Joomla > Drupal >
// Magento > Shopify > Ghost > PrestaShop > OpenCart > TYPO3 > Umbraco >
// Craft > Moodle) is an arbitrary but deterministic tie-break for
// the practically-impossible case of multiple CMS technologies matching one
// target.
export function getCmsType(technologies: DetectedTech[]): CmsType | null {
  const names = new Set(technologies.map((t) => t.name));
  if (names.has("WordPress")) return "wordpress";
  if (names.has("Joomla")) return "joomla";
  if (names.has("Drupal")) return "drupal";
  if (names.has("Magento")) return "magento";
  if (names.has("Shopify")) return "shopify";
  if (names.has("Ghost")) return "ghost";
  if (names.has("PrestaShop")) return "prestashop";
  if (names.has("OpenCart")) return "opencart";
  if (names.has("TYPO3")) return "typo3";
  if (names.has("Umbraco")) return "umbraco";
  if (names.has("Craft CMS")) return "craft";
  if (names.has("Moodle")) return "moodle";
  return null;
}

// ---- Engine ---------------------------------------------------------------

export async function checkFingerprint(targetUrl: string): Promise<FingerprintResult> {
  try {
    const res = await fetch(targetUrl, { redirect: "follow", signal: AbortSignal.timeout(10_000) });
    const html = await res.text();
    const headers = res.headers;

    const detected: DetectedTech[] = [];

    for (const pattern of PATTERNS) {
      let version: string | null = null;
      let packagedBy: string | null = null;
      let matchedHeader = false;
      let matchedHtml = false;

      if (pattern.headers) {
        for (const [headerName, regex] of Object.entries(pattern.headers)) {
          const val = headers.get(headerName);
          if (val && regex.test(val)) {
            matchedHeader = true;
            if (pattern.versionGroup) {
              const m = val.match(regex);
              if (m?.[pattern.versionGroup]) {
                version = m[pattern.versionGroup];
                packagedBy = distroFromHeader(val);
              }
            }
            break;
          }
        }
      }

      if (pattern.html) {
        const m = html.match(pattern.html);
        if (m) {
          matchedHtml = true;
          if (pattern.versionGroup && m[pattern.versionGroup]) {
            version = m[pattern.versionGroup];
          }
        }
      }

      if (!matchedHeader && !matchedHtml) continue;

      // Avoid duplicates — update if version is newly found.
      const existing = detected.find((d) => d.name === pattern.name);
      if (existing) {
        if (!existing.version && version) existing.version = version;
        if (matchedHeader && matchedHtml) existing.source = "both";
        continue;
      }

      const source = matchedHeader && matchedHtml ? "both" : matchedHeader ? "header" : "html";
      const confidence = source === "both" ? "high" : matchedHeader ? "high" : "medium";
      detected.push({ name: pattern.name, category: pattern.category, version, confidence, source, ...(packagedBy ? { packagedBy } : {}) });
    }

    const riskySoftware: RiskyTech[] = [];
    for (const tech of detected) {
      if (!tech.version) continue;
      const major = parseInt(tech.version.split(".")[0], 10);
      const risky = KNOWN_RISKY.find((r) => r.name === tech.name && major < r.maxSafeMajor);
      if (risky) {
        riskySoftware.push({ name: tech.name, version: tech.version, reason: risky.reason });
      }
    }

    return { status: "checked", technologies: detected, riskySoftware };
  } catch (err) {
    return { status: "error", note: `Fingerprint check failed: ${(err as Error).message}` };
  }
}

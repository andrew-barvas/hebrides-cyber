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
};

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

  // ---- Frameworks (header-detected) -----------------------------------------
  { name: "Next.js", category: "Framework", headers: { "x-nextjs-cache": /.+/, "x-powered-by": /Next\.js/i } },
  { name: "Nuxt.js", category: "Framework", headers: { "x-powered-by": /Nuxt/i } },
  { name: "Ruby on Rails", category: "Framework", headers: { "x-powered-by": /Phusion Passenger/i } },
  { name: "Django", category: "Framework", headers: { "x-frame-options": /SAMEORIGIN/i, "x-content-type-options": /nosniff/i, server: /Django|Gunicorn|uWSGI/i } },
  { name: "Laravel", category: "Framework", html: /laravel_session|_token.*csrf/i },

  // ---- CMS -----------------------------------------------------------------
  { name: "WordPress", category: "CMS", html: /wp-content|wp-includes|generator.*WordPress (\d+\.\d+)/i, versionGroup: 1 },
  { name: "Drupal", category: "CMS", html: /Drupal(?:\.settings|\/(\d+))/i, versionGroup: 1, headers: { "x-generator": /Drupal (\d+)/i } },
  { name: "Joomla", category: "CMS", html: /\/media\/jui\/|Joomla! - Open Source Content Management/i },
  { name: "Ghost", category: "CMS", html: /ghost-root|content="Ghost (\d+\.\d+)/i, versionGroup: 1 },
  { name: "Shopify", category: "E-commerce", html: /cdn\.shopify\.com|Shopify\.theme/i, headers: { "x-shopify-stage": /.+/ } },
  { name: "Magento", category: "E-commerce", html: /Mage\.(?:Cookies|Config)|\/skin\/frontend\//i },
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
export const DETECTABLE_TECHNOLOGIES: string[] = PATTERNS.map((p) => p.name);

// ---- Engine ---------------------------------------------------------------

export async function checkFingerprint(targetUrl: string): Promise<FingerprintResult> {
  try {
    const res = await fetch(targetUrl, { redirect: "follow", signal: AbortSignal.timeout(10_000) });
    const html = await res.text();
    const headers = res.headers;

    const detected: DetectedTech[] = [];

    for (const pattern of PATTERNS) {
      let version: string | null = null;
      let matchedHeader = false;
      let matchedHtml = false;

      if (pattern.headers) {
        for (const [headerName, regex] of Object.entries(pattern.headers)) {
          const val = headers.get(headerName);
          if (val && regex.test(val)) {
            matchedHeader = true;
            if (pattern.versionGroup) {
              const m = val.match(regex);
              if (m?.[pattern.versionGroup]) version = m[pattern.versionGroup];
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
      detected.push({ name: pattern.name, category: pattern.category, version, confidence, source });
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

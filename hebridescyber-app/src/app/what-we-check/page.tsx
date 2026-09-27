import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "What We Check — Hebrides Cyber",
  description:
    "Every automated check Hebrides Cyber's Security Score scan runs, in full technical detail — TLS, headers, DNS, exposed files, cloud misconfig, CMS deep scans, and more.",
};

// Content mirrors the check categories in src/lib/scanners/index.ts's
// ScanResults/summariseResults — keep this in sync when a new scanner module
// is added there.
type CheckCategory = {
  id: string;
  icon: string;
  name: string;
  badge?: "Runs on every scan" | "Runs when detected" | "Optional (ZAP)" | "Optional (Agency)";
  desc: string;
  checks: string[];
};

const categories: CheckCategory[] = [
  {
    id: "tls",
    icon: "🔒",
    name: "TLS & Certificates",
    badge: "Runs on every scan",
    desc: "Confirms traffic is actually encrypted, and that the certificate and protocol backing that encryption are sound.",
    checks: [
      "HTTPS enforced (not just available)",
      "Weak protocol detection (TLS 1.0/1.1 still enabled)",
      "Certificate expiry — flagged inside 21 days",
      "Self-signed certificate detection",
      "HSTS presence and max-age adequacy (≥180 days)",
    ],
  },
  {
    id: "headers",
    icon: "🛡️",
    name: "Security Headers & CSP",
    badge: "Runs on every scan",
    desc: "Checks the response headers that stop a browser doing something dangerous with your content, even after everything else is right.",
    checks: [
      "OWASP-recommended header set (HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy…)",
      "Content-Security-Policy graded A–F — unsafe-inline, unsafe-eval, and wildcard sources all cost points",
      "Cookie flags: Secure, HttpOnly, SameSite",
      "CORS wildcard origin (Access-Control-Allow-Origin: *)",
      "Server/technology version disclosure in headers",
    ],
  },
  {
    id: "dns",
    icon: "📧",
    name: "DNS & Email Authentication",
    badge: "Runs on every scan",
    desc: "Whether your domain can be spoofed for phishing, and whether your certificate issuance is locked down.",
    checks: [
      "SPF record present and correctly scoped",
      "DKIM key discovery across the default selectors used by major providers, plus key strength, revocation, and testing-mode checks",
      "DMARC record present, and enforcement policy (none / quarantine / reject)",
      "MTA-STS policy published and enforced, for domains that receive mail",
      "TLS-RPT reporting address configured, so failed mail-TLS connections are visible",
      "CAA records restricting which CAs can issue certificates for your domain",
      "DNSSEC signing status",
    ],
  },
  {
    id: "exposure",
    icon: "📂",
    name: "Sensitive File Exposure",
    badge: "Runs on every scan",
    desc: "Probes for the specific files that leak credentials or source code when a deployment forgets to exclude them — with false-positive hardening (see below) so a catch-all SPA doesn't get flagged for everything.",
    checks: [
      "Git/SVN metadata (.git/HEAD, .git/config, .svn/entries)",
      "Environment files (.env, .env.production, .env.backup)",
      "Framework config (config.php, wp-config.php.bak, settings.py, database.yml)",
      "Backup archives and raw SQL dumps",
      "Debug/admin pages (phpinfo, server-status, Symfony profiler, Laravel Telescope)",
      "Credential files (.htpasswd, .htaccess) and application logs",
      "security.txt presence (credited, not penalised, when found)",
    ],
  },
  {
    id: "directory-listing",
    icon: "🗂️",
    name: "Directory Listing (Autoindex)",
    badge: "Runs on every scan",
    desc: "Looks for Apache/nginx directory browsing left switched on for uploads, backups, and log folders — scoped narrowly to genuine autoindex pages (an \"Index of /…\" title plus a Parent Directory link), not just any page that happens to load at a common path.",
    checks: [
      "/uploads/, /backup/, /files/, /media/, /downloads/ and similar common paths",
      "/logs/, /tmp/, /data/, /wp-content/uploads/",
      "Approximate file count when a listing is found",
    ],
  },
  {
    id: "cloud-misconfig",
    icon: "☁️",
    name: "Cloud Storage Misconfiguration",
    badge: "Runs on every scan",
    desc: "Extracts S3, Azure Blob, and GCS references from your own page source, then tests only those specific buckets for public listing. Never guesses bucket names — that would mean scanning infrastructure you don't own.",
    checks: [
      "S3 buckets referenced in your site — tested for public ListBucketResult",
      "Azure Blob containers — tested for public EnumerationResults",
      "GCS buckets — tested via the same S3-compatible listing check",
    ],
  },
  {
    id: "fingerprint",
    icon: "🔬",
    name: "Technology Fingerprinting",
    badge: "Runs on every scan",
    desc: "Passive, Wappalyzer-style identification of your stack from headers and page source — no active probing, just pattern matching on what's already public.",
    checks: [
      "40+ frameworks, CMSes, servers, CDNs, and third-party services detected",
      "Version extraction where the response reveals one",
      "Known-outdated major versions flagged (jQuery, Bootstrap, WordPress, Angular, PHP, Apache)",
    ],
  },
  {
    id: "ports",
    icon: "🔌",
    name: "Open Ports & Network Exposure",
    badge: "Runs on every scan",
    desc: "Checks which ports are visible to the internet using Shodan's InternetDB — no port-scanning traffic sent to your infrastructure directly.",
    checks: [
      "Administrative and database ports that shouldn't be public (SSH, RDP, MySQL, PostgreSQL, MongoDB, Redis)",
      "Risk-rated per port with the reason it matters",
    ],
  },
  {
    id: "playwright",
    icon: "🖥️",
    name: "Headless Browser & Page Health",
    badge: "Runs on every scan",
    desc: "Actually loads the page in a real browser engine, the way a visitor would — catches problems a plain HTTP fetch can't see.",
    checks: [
      "Page load status and health",
      "Mixed content — HTTP resources loaded on an HTTPS page",
      "Browser console errors",
    ],
  },
  {
    id: "recon",
    icon: "🛰️",
    name: "Reconnaissance",
    badge: "Runs on every scan",
    desc: "Passive intelligence gathering from public sources — nothing sent to your infrastructure beyond a standard page request.",
    checks: [
      "CVEs Shodan associates with your IP's exposed services",
      "Subdomains discovered via Certificate Transparency logs (crt.sh)",
    ],
  },
  {
    id: "takeover",
    icon: "🪝",
    name: "Dangling DNS & Subdomain Takeover",
    badge: "Runs on every scan",
    desc: "Subdomains still pointing at cloud resources you've deleted — which someone else could re-create to serve content on your domain. Detection only: we never try to claim anything.",
    checks: [
      "Your site and every subdomain in Certificate Transparency logs checked for CNAMEs to Azure, AWS, GitHub Pages, Heroku, Shopify and other providers",
      "Reported only with proof the resource is gone: the provider's name doesn't exist (NXDOMAIN), or the provider's own \"unclaimed\" page is served",
    ],
  },
  {
    id: "domain",
    icon: "🗓️",
    name: "Domain Registration",
    badge: "Runs on every scan",
    desc: "The one renewal that takes your website and your email down together. Read from your registry's own RDAP record.",
    checks: [
      "Registration expiry date — flagged 30 days out, and urgently inside 14",
      "Registrar transfer lock on generic TLDs (.com, .net, .org and similar)",
    ],
  },
  {
    id: "webapp",
    icon: "🧩",
    name: "Web Application Security",
    badge: "Runs on every scan",
    desc: "A grab-bag of checks that don't fit a single category but catch some of the most common real-world misconfigurations.",
    checks: [
      "robots.txt reviewed for sensitive disallowed paths it inadvertently advertises",
      "Dangerous HTTP methods enabled (PUT, DELETE, TRACE)",
      "Error pages that leak stack traces or framework internals",
      "CORS reflected-Origin misconfiguration (with or without credentials allowed)",
      "JavaScript library versions (jQuery, Moment.js, Lodash, Bootstrap, AngularJS…) matched against live CVE data from OSV.dev",
      "Cross-origin scripts and stylesheets loaded without a Subresource Integrity hash",
    ],
  },
  {
    id: "cms",
    icon: "🧱",
    name: "CMS-Specific Deep Scans",
    badge: "Runs when detected",
    desc: "Once fingerprinting identifies WordPress, Joomla, or Drupal, a second pass runs checks specific to that platform.",
    checks: [
      "WordPress: XML-RPC exposure, REST API user enumeration, debug.log, readme.html version disclosure, wp-cron.php",
      "Joomla: core version disclosure via the administrator manifest, leftover installer files",
      "Drupal: core version disclosure via CHANGELOG.txt, update.php reachability, public JSON:API, uid 1 profile enumeration",
    ],
  },
  {
    id: "zap",
    icon: "⚡",
    name: "Active Application Scanning (OWASP ZAP)",
    badge: "Optional (ZAP)",
    desc: "Where a ZAP instance is configured, an active spider/scan can be triggered against the target for deeper coverage than passive checks alone. Off by default — active scanning sends real attack payloads, so it only runs where explicitly enabled for a verified target.",
    checks: ["Spidering and active vulnerability scanning via a connected ZAP daemon"],
  },
  {
    id: "authenticated",
    icon: "🔑",
    name: "Authenticated Scanning",
    badge: "Optional (Agency)",
    desc: "Connect a session cookie or Basic Auth credential for a monitored site and the same header/cookie/CSP/CORS checks re-run against the authenticated page — not a full crawl behind login, and not access-control (IDOR) testing. The one thing this uncovers that nothing else in this suite can: a real session cookie with insecure flags, which is invisible until you're actually logged in.",
    checks: [
      "Missing security headers on the authenticated page",
      "Session cookies missing Secure/HttpOnly/SameSite — graded more seriously than the same issue on a public page",
      "CSP and CORS misconfiguration on authenticated responses",
    ],
  },
];

function CategoryCard({ category }: { category: CheckCategory }) {
  return (
    <div className="group relative rounded-lg border border-cyberborder bg-cyberpanel p-5 transition duration-200 hover:border-neon/50 hover:shadow-glowsm flex flex-col">
      <div className="mb-3 flex items-start gap-3">
        <span className="text-xl flex-shrink-0 mt-0.5">{category.icon}</span>
        <div className="flex-1">
          <div className="flex items-start justify-between gap-2">
            <h3 className="font-mono text-sm font-semibold text-neon leading-snug">{category.name}</h3>
            {category.badge && (
              <span className="flex-shrink-0 rounded-full bg-neon/10 px-2 py-0.5 text-xs font-medium text-neon border border-neon/20">
                {category.badge}
              </span>
            )}
          </div>
          <p className="mt-1.5 text-sm text-cybertext/70 leading-relaxed">{category.desc}</p>
        </div>
      </div>

      <ul className="mt-3 space-y-1.5 flex-1">
        {category.checks.map((item) => (
          <li key={item} className="flex items-start gap-2 text-xs text-cybertext/60">
            <span className="flex-shrink-0 mt-0.5 text-neon/50">›</span>
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function WhatWeCheckPage() {
  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      {/* Hero */}
      <div className="relative overflow-hidden border-b border-cyberborder px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> cat ./scanner/checks.log
          </p>
          <h1 className="mx-auto max-w-2xl text-4xl font-bold sm:text-5xl">What we check</h1>
          <p className="mx-auto mt-4 max-w-2xl text-cybertext/70">
            Every check listed here runs automatically as part of a Security Score scan. Nothing is
            hidden behind &ldquo;proprietary methodology&rdquo; — this is the actual list, kept in sync
            with the scanner code.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <Link
              href="/dashboard"
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Run a free scan
            </Link>
            <Link
              href="/services"
              className="rounded-md border border-cybertext/20 px-6 py-2.5 text-sm font-semibold text-cybertext hover:border-neon hover:text-neon"
            >
              View services
            </Link>
          </div>
        </div>
      </div>

      {/* Categories */}
      <div className="mx-auto max-w-5xl px-6 py-16">
        <div className="mb-8">
          <p className="mb-1 font-mono text-xs text-neon/60">// scan categories</p>
          <p className="text-sm text-cybertext/50">
            Every check is read-only and passive by default — no exploit payloads, no destructive
            requests. The one exception is the optional ZAP active scan, which only runs where
            it&apos;s explicitly configured against a domain you&apos;ve already verified you own.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          {categories.map((c) => (
            <CategoryCard key={c.id} category={c} />
          ))}
        </div>

        {/* How results are scored and explained */}
        <div className="mt-16">
          <div className="mb-5 flex items-center gap-3" aria-hidden="true">
            <span className="font-mono text-xs text-neon/60">// after the scan</span>
            <div className="h-px flex-1 bg-cyberborder" />
          </div>
          <h2 className="mb-1 text-xl font-bold text-cybertext">How every finding is scored and explained</h2>
          <p className="mb-6 text-sm text-cybertext/50">
            Running the checks is half the product — turning results into something you can act on is
            the other half.
          </p>
          <div className="grid gap-4 sm:grid-cols-2">
            <CategoryCard
              category={{
                id: "scoring",
                icon: "📊",
                name: "Severity scoring",
                desc: "Every finding is rated critical, high, medium, low, or info, and rolled up into a single score out of 100 so you can track improvement over time.",
                checks: [
                  "Critical/high/medium/low/info severity on every finding",
                  "0–100 score with weighted penalties per severity",
                  "Score trend chart across every past scan of the same target",
                ],
              }}
            />
            <CategoryCard
              category={{
                id: "cve",
                icon: "🧬",
                name: "Live CVE references",
                desc: "Where a finding is a known-vulnerable JS library, we look up real CVE IDs from OSV.dev at scan time rather than relying on a hardcoded list that goes stale.",
                checks: [
                  "Live OSV.dev lookup for vulnerable JS libraries",
                  "Checks both direct advisory IDs and GHSA aliases",
                  "Falls back gracefully — no CVE claimed if OSV.dev is unreachable",
                ],
              }}
            />
            <CategoryCard
              category={{
                id: "exploited",
                icon: "🎯",
                name: "Known-exploited flags",
                desc: "Severity says how bad a flaw could be; this says whether attackers are using it. Every CVE we report is checked against CISA's Known Exploited Vulnerabilities catalog and scored with FIRST's EPSS model, and your report sorts the exploited ones first.",
                checks: [
                  "\"Actively exploited\" when a CVE is in CISA's KEV catalog, with ransomware use called out",
                  "EPSS: the probability of exploitation activity in the next 30 days",
                  "Never guessed — if either source is unreachable, the flag is left off rather than shown as safe",
                ],
              }}
            />
            <CategoryCard
              category={{
                id: "remediation",
                icon: "🛠️",
                name: "Copy-pasteable remediation",
                desc: "Every finding type ships with specific fix instructions — config snippets for nginx, Apache, Next.js, and Azure Static Web Apps where relevant, not generic advice.",
                checks: [
                  "Per-finding Markdown remediation with real config snippets",
                  "Automated PRs available — findings become an actual pull request with a SECURITY-FIXES.md",
                  "AI-tailored guidance available on request for your specific detected stack",
                ],
              }}
            />
            <CategoryCard
              category={{
                id: "diffing",
                icon: "🔁",
                name: "Scan-to-scan comparison",
                desc: "Every finding carries a stable identity, so re-scanning the same target shows exactly what's new and what's been fixed — not just a fresh, unrelated list.",
                checks: [
                  "New vs. fixed vs. unchanged, compared against your last scan",
                  "Shareable, read-only report links for clients or auditors",
                  "Exportable PDF reports",
                ],
              }}
            />
          </div>
        </div>

        {/* How we avoid false positives */}
        <div id="methodology" className="mt-16 scroll-mt-24">
          <div className="mb-5 flex items-center gap-3" aria-hidden="true">
            <span className="font-mono text-xs text-neon/60">// methodology</span>
            <div className="h-px flex-1 bg-cyberborder" />
          </div>
          <h2 className="mb-1 text-xl font-bold text-cybertext">How we avoid false positives</h2>
          <p className="mb-6 text-sm text-cybertext/50">
            The single biggest failure mode for this kind of scanning is a catch-all site that
            returns 200 for every URL — naively probed, that looks like every sensitive file and
            every admin panel exists. Here&apos;s specifically what stops that.
          </p>
          <div className="grid gap-4 sm:grid-cols-2">
            <CategoryCard
              category={{
                id: "baseline",
                icon: "🧪",
                name: "Known-404 baseline first",
                desc: "Before probing anything real, every path-probing check fingerprints the site root and a random, guaranteed-nonexistent URL. If that random URL returns 200, the site serves a catch-all — and every subsequent probe gets compared against that baseline, not treated as a finding on its own.",
                checks: [
                  "Shared across every path-probing check (src/lib/scanners/httpProbe.ts) — one proven implementation, not a copy per scanner",
                  "ETag / Content-Length compared against the site root as a first, cheap signal",
                ],
              }}
            />
            <CategoryCard
              category={{
                id: "masking",
                icon: "🎭",
                name: "Path-masked body comparison",
                desc: "Catch-all shells often echo the requested URL back into the page (a router, a canonical link, an error message) — which would otherwise make every probed path look like a different document, and can accidentally satisfy a content check by pure coincidence. The probed path is masked out of both bodies before they're ever compared.",
                checks: [
                  "Prefix/suffix similarity match on the masked bodies — ≥85% shared content counts as \"the same page\"",
                  "Applied identically whether the probe is for a leaked .env file or an open directory listing",
                ],
              }}
            />
            <CategoryCard
              category={{
                id: "assertions",
                icon: "✅",
                name: "Content assertions, not just status codes",
                desc: "A 200 response alone is never enough to call something exposed. Each check asserts the body actually looks like what it claims to have found.",
                checks: [
                  "A .env \"hit\" must match a real KEY=value assignment pattern, not just any 200",
                  "A directory listing must show both an \"Index of /...\" title and a Parent Directory link — a page that merely loads at /uploads/ (an upload form, say) doesn't count",
                  "A .htpasswd \"hit\" must match a real password-hash line format",
                ],
              }}
            />
            <CategoryCard
              category={{
                id: "scoped",
                icon: "🎯",
                name: "Scoped to evidence we actually have",
                desc: "Every check only reports what it can back up — no guessing at what \"might\" be there.",
                checks: [
                  "Cloud misconfig only tests buckets the target's own page source references — never guesses bucket names against infrastructure the customer doesn't own",
                  "CVE references come from a live OSV.dev lookup against the exact detected version — no CVE claimed if the lookup fails or nothing matches",
                  "CMS deep scans (WordPress/Joomla/Drupal) only run once fingerprinting has actually detected that CMS",
                ],
              }}
            />
          </div>
        </div>

        {/* What this can't detect */}
        <div className="mt-16">
          <div className="mb-5 flex items-center gap-3" aria-hidden="true">
            <span className="font-mono text-xs text-neon/60">// limits</span>
            <div className="h-px flex-1 bg-cyberborder" />
          </div>
          <h2 className="mb-1 text-xl font-bold text-cybertext">What this can&apos;t detect</h2>
          <p className="mb-6 text-sm text-cybertext/50">
            Automated scanning is genuinely good at what&apos;s listed above, and genuinely bad at
            everything below. Worth knowing before you treat a clean scan as a clean bill of health.
          </p>
          <div className="rounded-xl border border-cyberborder bg-cyberpanel p-6">
            <ul className="space-y-3 text-sm text-cybertext/70">
              <li className="flex gap-3">
                <span className="flex-shrink-0 text-amber-400">▸</span>
                <span>
                  <strong className="text-cybertext">Business logic flaws</strong> — price manipulation,
                  privilege escalation through a legitimate workflow, coupon/quantity abuse. These
                  require understanding what the application is <em>supposed</em> to do, which no
                  automated scan can infer.
                </span>
              </li>
              <li className="flex gap-3">
                <span className="flex-shrink-0 text-amber-400">▸</span>
                <span>
                  <strong className="text-cybertext">Deep authenticated testing</strong> — every
                  scan here is unauthenticated (black-box against the public site) by default. Connecting a
                  session cookie or Basic Auth credential (Agency plan) re-runs header/cookie/CSP/CORS
                  checks against the logged-in page, but that&apos;s a narrow recheck, not a crawl behind
                  login. Access-control bugs that only show up once you&apos;re logged in as one user trying
                  to reach another user&apos;s data (IDOR), and multi-step auth flows (OAuth, MFA), aren&apos;t
                  covered.
                </span>
              </li>
              <li className="flex gap-3">
                <span className="flex-shrink-0 text-amber-400">▸</span>
                <span>
                  <strong className="text-cybertext">Zero-days and unknown vulnerabilities</strong> —
                  nuclei and the fingerprinting checks match against known template/CVE databases.
                  Anything not yet publicly known or catalogued won&apos;t be flagged.
                </span>
              </li>
              <li className="flex gap-3">
                <span className="flex-shrink-0 text-amber-400">▸</span>
                <span>
                  <strong className="text-cybertext">DKIM on a custom selector</strong> — a DKIM key
                  lives at a selector name chosen freely by whoever set it up, and it cannot be
                  discovered from DNS. We probe the defaults the major providers use, so finding a key
                  is real evidence, but not finding one isn&apos;t proof of absence. We report that
                  case as informational, never as &ldquo;DKIM missing&rdquo;.
                </span>
              </li>
              <li className="flex gap-3">
                <span className="flex-shrink-0 text-amber-400">▸</span>
                <span>
                  <strong className="text-cybertext">Real active scanning, most of the time</strong> —
                  nmap/nuclei/sqlmap/XSSer/commix/a real ZAP active scan only run on the scheduled monitoring path,
                  where domain ownership has already been verified. An on-demand dashboard scan is
                  passive/read-only checks only.
                </span>
              </li>
              <li className="flex gap-3">
                <span className="flex-shrink-0 text-amber-400">▸</span>
                <span>
                  <strong className="text-cybertext">Physical, social, and process risk</strong> — phishing
                  susceptibility, insider threats, physical access controls, offline backup hygiene. None
                  of that is visible from the outside of a website.
                </span>
              </li>
            </ul>
            <p className="mt-5 text-xs text-cybertext/50">
              For the things on this list, see{" "}
              <Link href="/services" className="text-neon underline hover:text-cybertext">
                manual penetration testing
              </Link>{" "}
              — a human tester, not a scanner, is what actually finds these.
            </p>
          </div>
        </div>

        {/* CTA */}
        <div className="mt-16 rounded-xl border border-neon/30 bg-cyberpanel p-8 text-center">
          <p className="mb-1 font-mono text-xs text-neon/60">// ready?</p>
          <h2 className="mb-2 text-2xl font-bold">See it run against your own site</h2>
          <p className="mb-6 text-cybertext/70">
            Free scan, one-page report in 24 hours, no commitment.
          </p>
          <Link
            href="/dashboard"
            className="inline-block rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
          >
            Run a free scan
          </Link>
        </div>
      </div>
    </div>
  );
}

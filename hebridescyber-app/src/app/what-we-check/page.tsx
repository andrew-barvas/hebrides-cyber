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
  badge?: "Runs on every scan" | "Runs when detected" | "Optional (ZAP)";
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
      "DMARC record present, and enforcement policy (none / quarantine / reject)",
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
            requests. The one exception is the optional ZAP active scan, which only runs where it's
            explicitly configured against a domain you've already verified you own.
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

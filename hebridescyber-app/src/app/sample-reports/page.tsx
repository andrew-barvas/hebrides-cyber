import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Sample Security Reports — Hebrides Cyber",
  description:
    "Illustrative sample reports showing what a Hebrides Cyber scan reports: the score, each finding with its severity, and the specific fix.",
};

// Illustrative examples: fictional sites, built from the kinds of findings
// our checks actually report. Never present these as real customer scans —
// there is no customer data behind them.
type Finding = {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  detail: string;
  remediation: string;
};

type SampleReport = {
  slug: string;
  label: string;
  siteType: string;
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  tlsGrade: string;
  headerScore: number;
  dnsScore: number;
  findings: Finding[];
  summary: string;
  fixedIn?: string;
};

const SEVERITY_COLOR: Record<Finding["severity"], string> = {
  critical: "text-red-400 border-red-400/30 bg-red-400/10",
  high: "text-orange-400 border-orange-400/30 bg-orange-400/10",
  medium: "text-yellow-400 border-yellow-400/30 bg-yellow-400/10",
  low: "text-blue-400 border-blue-400/30 bg-blue-400/10",
  info: "text-cybertext/50 border-cyberborder bg-cyberbg/50",
};

const GRADE_COLOR: Record<SampleReport["grade"], string> = {
  A: "text-neon border-neon/30 bg-neon/10",
  B: "text-blue-400 border-blue-400/30 bg-blue-400/10",
  C: "text-yellow-400 border-yellow-400/30 bg-yellow-400/10",
  D: "text-orange-400 border-orange-400/30 bg-orange-400/10",
  F: "text-red-400 border-red-400/30 bg-red-400/10",
};

const samples: SampleReport[] = [
  {
    slug: "small-retail",
    label: "Small retail — before remediation",
    siteType: "E-commerce (WooCommerce)",
    score: 34,
    grade: "F",
    tlsGrade: "B",
    headerScore: 20,
    dnsScore: 40,
    summary:
      "Typical score for a small e-commerce site that hasn't had a security review. WordPress + WooCommerce with an outdated plugin, no DMARC, and several missing security headers. Score recovered to 81 within two weeks after following the remediation plan.",
    fixedIn: "81/100 after remediation",
    findings: [
      {
        id: "wp-plugin-vuln",
        title: "WooCommerce Payments 7.2.1 — known RCE (CVE-2024-9998)",
        severity: "critical",
        category: "CMS / Plugins",
        detail:
          "An unauthenticated attacker can trigger a privilege escalation and achieve remote code execution. The site is running version 7.2.1; the patch was released in 7.3.0.",
        remediation: "Update WooCommerce Payments to ≥ 7.3.0 via Plugins → Updates in WP Admin.",
      },
      {
        id: "no-dmarc",
        title: "No DMARC record — domain can be used to spoof email",
        severity: "high",
        category: "DNS / Email",
        detail:
          "Without a DMARC record, anyone can send email that appears to come from your domain. This is the #1 enabler of phishing attacks targeting your customers.",
        remediation:
          'Add a TXT record: _dmarc.example.com → "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"',
      },
      {
        id: "no-csp",
        title: "Content-Security-Policy header missing",
        severity: "medium",
        category: "Security Headers",
        detail:
          "Without a CSP, the browser will execute any script the page loads — including scripts injected by an attacker who exploits an XSS vulnerability.",
        remediation:
          "Add Content-Security-Policy to the server's response headers. Start with a report-only policy to avoid breaking the site.",
      },
      {
        id: "php-version",
        title: "PHP version disclosed in X-Powered-By header",
        severity: "low",
        category: "Information Disclosure",
        detail: "X-Powered-By: PHP/8.1.12 — minor version tells an attacker exactly which PHP CVEs to try.",
        remediation: "Remove the header: set expose_php = Off in php.ini and remove_header X-Powered-By in nginx/Apache config.",
      },
    ],
  },
  {
    slug: "professional-services",
    label: "Professional services firm",
    siteType: "Corporate (Next.js / Vercel)",
    score: 72,
    grade: "B",
    tlsGrade: "A",
    headerScore: 70,
    dnsScore: 80,
    summary:
      "Modern Next.js app on Vercel with a generally good baseline — TLS grade A, HSTS in place, SPF and DMARC both set. Losing points on a weak CSP (unsafe-inline from third-party scripts) and a missing Permissions-Policy. No critical or high findings.",
    findings: [
      {
        id: "csp-unsafe-inline",
        title: "CSP contains 'unsafe-inline' — XSS protections weakened",
        severity: "medium",
        category: "Security Headers / CSP",
        detail:
          "'unsafe-inline' in script-src lets the browser run any inline <script> tag. If an attacker can inject any HTML they can run arbitrary JavaScript.",
        remediation:
          "Switch to a nonce-based CSP. Next.js 14+ supports automatic nonce injection via middleware. Remove 'unsafe-inline' once all inline scripts use the nonce.",
      },
      {
        id: "permissions-policy",
        title: "Permissions-Policy header missing",
        severity: "low",
        category: "Security Headers",
        detail:
          "Browser features (microphone, camera, payment, geolocation) are unrestricted. An XSS payload could silently activate them.",
        remediation:
          "Add Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=() to response headers.",
      },
      {
        id: "caa-missing",
        title: "No CAA DNS records — any CA can issue certs for this domain",
        severity: "low",
        category: "DNS",
        detail:
          "Certification Authority Authorisation records constrain which CAs can issue certificates. Without them, a rogue CA could issue a cert for your domain.",
        remediation: 'Add CAA records: 0 issue "letsencrypt.org" and 0 issuewild ";"',
      },
    ],
  },
  {
    slug: "saas-platform",
    label: "SaaS platform — after security programme",
    siteType: "SaaS (React + Node.js API)",
    score: 94,
    grade: "A",
    tlsGrade: "A+",
    headerScore: 95,
    dnsScore: 100,
    summary:
      "Result after a 6-month security improvement programme. TLS grade A+, strict CSP with nonces, DMARC p=reject, CAA records, HSTS preloaded. One remaining medium — a third-party analytics script loaded over HTTP from a subdomain — and two informational findings. No critical, high, or any unaddressed medium.",
    findings: [
      {
        id: "mixed-content",
        title: "Analytics script loaded over HTTP from cdn.metrics.example.io",
        severity: "medium",
        category: "Mixed Content",
        detail:
          "The main page loads a metrics script over plain HTTP. This allows an attacker on the same network to replace the script with malicious code.",
        remediation: "Update the script tag src to https:// — the CDN endpoint supports HTTPS.",
      },
      {
        id: "hsts-preload-pending",
        title: "HSTS preload: submitted, not yet in Chrome's list",
        severity: "info",
        category: "TLS / HSTS",
        detail: "The HSTS preload submission was accepted but Chrome's list update is typically 6–8 weeks. No action needed.",
        remediation: "No action required — list inclusion is pending.",
      },
    ],
  },
];

function ScoreRing({ score }: { score: number }) {
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 45 ? "D" : "F";
  const color =
    grade === "A"
      ? "#39FFC0"
      : grade === "B"
      ? "#60a5fa"
      : grade === "C"
      ? "#facc15"
      : grade === "D"
      ? "#fb923c"
      : "#f87171";
  const r = 32;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="88" height="88" viewBox="0 0 88 88" className="rotate-[-90deg]">
        <circle cx="44" cy="44" r={r} fill="none" stroke="#1a2535" strokeWidth="8" />
        <circle
          cx="44"
          cy="44"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeDasharray={`${dash} ${circ - dash}`}
          strokeLinecap="round"
        />
      </svg>
      <div className="-mt-[72px] flex flex-col items-center">
        <span className="text-2xl font-bold" style={{ color }}>{score}</span>
        <span className="text-xs text-cybermuted font-mono -mt-0.5">/100</span>
      </div>
      <div className="mt-8" />
    </div>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  return (
    <div className="rounded-lg border border-cyberborder bg-cyberbg/50 p-4">
      <div className="flex items-start justify-between gap-3 mb-2">
        <p className="text-sm font-medium text-cybertext leading-snug">{finding.title}</p>
        <span
          className={`flex-shrink-0 rounded-full border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${SEVERITY_COLOR[finding.severity]}`}
        >
          {finding.severity}
        </span>
      </div>
      <p className="text-xs text-cybertext/50 mb-1">
        <span className="font-mono text-neon/60">[{finding.category}]</span>
      </p>
      <p className="text-xs text-cybertext/70 mb-2">{finding.detail}</p>
      <div className="rounded bg-neon/5 border border-neon/10 px-3 py-2">
        <p className="text-xs text-neon/70">
          <span className="font-mono text-neon/40">// fix: </span>
          {finding.remediation}
        </p>
      </div>
    </div>
  );
}

function ReportCard({ report }: { report: SampleReport }) {
  const critCount = report.findings.filter((f) => f.severity === "critical").length;
  const highCount = report.findings.filter((f) => f.severity === "high").length;
  const medCount = report.findings.filter((f) => f.severity === "medium").length;
  const lowCount = report.findings.filter((f) => f.severity === "low").length;

  return (
    <div className="rounded-xl border border-cyberborder bg-cyberpanel">
      {/* Header */}
      <div className="border-b border-cyberborder px-6 py-5 flex flex-col sm:flex-row sm:items-center gap-4">
        <ScoreRing score={report.score} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <h2 className="text-lg font-bold text-cybertext">{report.label}</h2>
            <span
              className={`rounded-full border px-2 py-0.5 text-xs font-bold ${GRADE_COLOR[report.grade]}`}
            >
              Grade {report.grade}
            </span>
            {report.fixedIn && (
              <span className="rounded-full border border-neon/30 bg-neon/10 px-2 py-0.5 text-xs font-medium text-neon">
                → {report.fixedIn}
              </span>
            )}
          </div>
          <p className="text-xs text-cybermuted font-mono mb-2">
            {report.siteType} · illustrative example
          </p>
          <p className="text-sm text-cybertext/70 leading-relaxed">{report.summary}</p>
          {/* Sub-scores */}
          <div className="mt-3 flex flex-wrap gap-3">
            <span className="text-xs text-cybertext/50">TLS <span className="font-mono text-cybertext">{report.tlsGrade}</span></span>
            <span className="text-xs text-cybertext/50">Headers <span className="font-mono text-cybertext">{report.headerScore}%</span></span>
            <span className="text-xs text-cybertext/50">DNS <span className="font-mono text-cybertext">{report.dnsScore}%</span></span>
          </div>
        </div>
        {/* Finding counts */}
        <div className="flex flex-row sm:flex-col gap-2 sm:items-end flex-shrink-0">
          {critCount > 0 && (
            <span className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${SEVERITY_COLOR.critical}`}>
              {critCount} critical
            </span>
          )}
          {highCount > 0 && (
            <span className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${SEVERITY_COLOR.high}`}>
              {highCount} high
            </span>
          )}
          {medCount > 0 && (
            <span className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${SEVERITY_COLOR.medium}`}>
              {medCount} medium
            </span>
          )}
          {lowCount > 0 && (
            <span className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${SEVERITY_COLOR.low}`}>
              {lowCount} low
            </span>
          )}
        </div>
      </div>

      {/* Findings */}
      <div className="px-6 py-5 space-y-3">
        <p className="font-mono text-xs text-cybermuted uppercase tracking-wide mb-3">// findings</p>
        {report.findings.map((f) => (
          <FindingRow key={f.id} finding={f} />
        ))}
      </div>
    </div>
  );
}

export default function SampleReportsPage() {
  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      {/* Hero */}
      <div className="relative overflow-hidden border-b border-cyberborder px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> cat ./reports/samples/*.json
          </p>
          <h1 className="mx-auto max-w-2xl text-4xl font-bold sm:text-5xl">Sample reports</h1>
          <p className="mx-auto mt-4 max-w-2xl text-cybertext/70">
            Illustrative examples — the sites are fictional, but every finding is one our checks really
            report. The layout matches a real Hebrides Cyber report: the score, each finding with its
            severity and category, and the specific fix for each. No proprietary scoring black boxes.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <Link
              href="/pricing"
              className="inline-flex items-center rounded-lg bg-neon px-5 py-2.5 text-sm font-semibold text-cyberbg hover:bg-neon/90 transition"
            >
              Run your own scan
            </Link>
            <Link
              href="/what-we-check"
              className="inline-flex items-center rounded-lg border border-cyberborder px-5 py-2.5 text-sm font-medium text-cybertext/80 hover:border-neon/50 hover:text-neon transition"
            >
              What we check
            </Link>
          </div>
        </div>
      </div>

      {/* Scoring explainer */}
      <div className="border-b border-cyberborder bg-cyberpanel/50">
        <div className="mx-auto max-w-4xl px-6 py-8">
          <h2 className="font-mono text-xs text-cybermuted uppercase tracking-wide mb-4">// how scores work</h2>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {[
              { sev: "Critical", pts: "−30", color: "text-red-400" },
              { sev: "High", pts: "−15", color: "text-orange-400" },
              { sev: "Medium", pts: "−7", color: "text-yellow-400" },
              { sev: "Low", pts: "−2", color: "text-blue-400" },
              { sev: "Info", pts: "0", color: "text-cybertext/50" },
            ].map(({ sev, pts, color }) => (
              <div key={sev} className="rounded-lg border border-cyberborder bg-cyberbg/60 p-3 text-center">
                <p className={`text-sm font-bold ${color}`}>{pts}</p>
                <p className="text-xs text-cybertext/50 mt-0.5">{sev}</p>
              </div>
            ))}
          </div>
          <p className="mt-4 text-sm text-cybertext/60">
            Score starts at 100 and each finding deducts the penalty for its severity. The floor is 0.
            Where a finding is tied to a known vulnerability, the penalty also reflects the real-world
            evidence: it costs more if the flaw is on CISA&rsquo;s Known Exploited Vulnerabilities list
            (or used in ransomware) or has a high exploitation probability (EPSS), and at least the
            penalty for its CVSS band. A flaw with a negligible measured exploitation probability costs
            less. One finding never costs more than 45 points. Scoring is transparent and
            deterministic — the same evidence always produces the same score, so you can track
            improvement over time.
          </p>
        </div>
      </div>

      {/* Reports */}
      <div className="mx-auto max-w-4xl px-6 py-12 space-y-10">
        {samples.map((report) => (
          <ReportCard key={report.slug} report={report} />
        ))}
      </div>

      {/* CTA */}
      <div className="border-t border-cyberborder">
        <div className="mx-auto max-w-2xl px-6 py-16 text-center">
          <h2 className="text-2xl font-bold mb-3">See how your site scores</h2>
          <p className="text-cybertext/60 mb-6 text-sm">
            Add your site and get your first scan free. No credit card, no sales call.
          </p>
          <Link
            href="/pricing"
            className="inline-flex items-center rounded-lg bg-neon px-6 py-3 font-semibold text-cyberbg hover:bg-neon/90 transition"
          >
            Start free scan
          </Link>
        </div>
      </div>
    </div>
  );
}

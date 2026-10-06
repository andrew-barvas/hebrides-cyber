import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "NCSC Web Check & Mail Check retired — the alternative for UK organisations — Hebrides Cyber",
  description:
    "NCSC retired Web Check and Mail Check on 31 March 2026 and now recommends commercial External Attack Surface Management. See how Hebrides Cyber covers the retired website and email checks — from £20/month, with one free scan.",
};

type Coverage = "full" | "partial";

type CheckRow = {
  /** What the retired NCSC service looked at. */
  ncsc: string;
  /** What we do about it, in plain terms. */
  us: string;
  coverage: Coverage;
  /** The scanner (or honest gap) behind the claim. */
  detail: string;
};

// Every "full" row maps to a check that runs on every scan today; every
// "partial" row states honestly what we do and don't do. Kept in step with
// docs/COMPETITIVE-ANALYSIS.md §12's NCSC-checklist mapping — do not upgrade
// a row to "full" here without the check actually shipping.
const webCheckRows: CheckRow[] = [
  {
    ncsc: "TLS/HTTPS configuration and certificates",
    us: "Certificate grade, expiry, self-signed and weak-protocol checks, plus HSTS",
    coverage: "full",
    detail: "Runs on every scan. A deeper testssl.sh pass runs on scheduled scans.",
  },
  {
    ncsc: "HTTP security headers",
    us: "The OWASP secure-header set, Content-Security-Policy grading, cookie flags and CORS",
    coverage: "full",
    detail: "Runs on every scan, with copy-pasteable fixes for nginx, Apache, Next.js and Azure.",
  },
  {
    ncsc: "DNS configuration",
    us: "SPF, DKIM, DMARC, MTA-STS, TLS-RPT, CAA and DNSSEC",
    coverage: "full",
    detail: "Runs on every scan. Email records are only judged when the domain actually receives mail.",
  },
  {
    ncsc: "Vulnerable and out-of-date software",
    us: "Technology fingerprinting, CVE matching for detected software and JS libraries, and open-port exposure",
    coverage: "full",
    detail: "Every CVE is checked against CISA's Known Exploited Vulnerabilities catalogue and scored for likelihood.",
  },
  {
    ncsc: "Exposed files and services",
    us: "Sensitive-path exposure, directory listing, and public cloud storage referenced by the site",
    coverage: "full",
    detail: "Reported only with evidence — a baseline request rules out sites that answer every path with their homepage.",
  },
  {
    ncsc: "Forgotten subdomains and dangling DNS",
    us: "Subdomains from Certificate Transparency logs, and a dangling-DNS / subdomain-takeover check",
    coverage: "partial",
    detail: "We check the subdomains we can see in public logs, and on paid plans tell you after each scan about any whose first certificate is new. We only see subdomains that have a certificate or public DNS record: we don't guess names.",
  },
];

const mailCheckRows: CheckRow[] = [
  {
    ncsc: "Email anti-spoofing (SPF, DKIM, DMARC)",
    us: "SPF scope, DKIM key discovery and strength, and DMARC presence and enforcement policy",
    coverage: "full",
    detail: "Runs on every scan and tells you whether your domain can be spoofed for phishing.",
  },
  {
    ncsc: "Email transport security (MTA-STS, TLS-RPT)",
    us: "MTA-STS policy published and enforced, and a TLS-RPT reporting address",
    coverage: "full",
    detail: "Checked live, not just from DNS, for domains that receive mail.",
  },
  {
    ncsc: "DMARC aggregate report analysis",
    us: "We check your DMARC record and policy, but do not yet receive and parse the aggregate (rua) reports themselves",
    coverage: "partial",
    detail: "This is the one part of Mail Check we don't fully replace yet. It needs a report mailbox and is on the roadmap.",
  },
  {
    ncsc: "Domain that underpins your email",
    us: "Registration expiry and registrar transfer-lock checks, read from the registry",
    coverage: "full",
    detail: "An expired domain takes your website and email down together — a gap Web Check and Mail Check didn't cover.",
  },
];

function CoverageBadge({ coverage }: { coverage: Coverage }) {
  if (coverage === "full") {
    return (
      <span className="inline-flex items-center rounded-full border border-neon/30 bg-neon/10 px-2 py-0.5 text-[11px] font-semibold text-neon">
        Covered
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center rounded-full border border-amber-400/30 bg-amber-400/10 px-2 py-0.5 text-[11px] font-semibold text-amber-400"
      title="We cover part of this. The detail says exactly what we do and don't do."
    >
      Partial
    </span>
  );
}

function CoverageTable({ rows, caption }: { rows: CheckRow[]; caption: string }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-cyberborder bg-cyberpanel">
      <table className="w-full min-w-[640px] text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr className="border-b border-cyberborder font-mono text-[11px] uppercase tracking-wider text-cybertext/50">
            <th scope="col" className="px-4 py-3 font-medium">What it checked</th>
            <th scope="col" className="px-4 py-3 font-medium">What we do</th>
            <th scope="col" className="px-4 py-3 font-medium">Coverage</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-cyberborder">
          {rows.map((row) => (
            <tr key={row.ncsc}>
              <th scope="row" className="px-4 py-3 align-top font-medium text-cybertext/90">
                {row.ncsc}
              </th>
              <td className="px-4 py-3 align-top text-cybertext/70">
                {row.us}
                <span className="mt-1 block text-xs text-cybertext/45">{row.detail}</span>
              </td>
              <td className="px-4 py-3 align-top">
                <CoverageBadge coverage={row.coverage} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function WebCheckAlternativePage() {
  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      <div className="relative overflow-hidden border-b border-cyberborder px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> ./check --replaces web-check mail-check
          </p>
          <h1 className="mx-auto max-w-3xl text-4xl font-bold sm:text-5xl">
            NCSC retired Web Check and Mail Check. Here&apos;s the alternative.
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-cybertext/70">
            On 31 March 2026 the NCSC retired its free Web Check and Mail Check services and now
            recommends commercial attack-surface products instead. Hebrides Cyber covers the website
            and email checks you lost — with plain-English fixes and one free scan to start.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <Link
              href="/dashboard"
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Run your free scan
            </Link>
            <Link
              href="/pricing"
              className="rounded-md border border-cybertext/20 px-6 py-2.5 text-sm font-semibold text-cybertext hover:border-neon hover:text-neon"
            >
              View pricing
            </Link>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-4xl px-6 py-16">
        {/* Facts, attributed. Nothing here implies NCSC endorses this product. */}
        <div className="mb-12 rounded-lg border border-cyberborder bg-cyberpanel p-6">
          <p className="mb-2 font-mono text-xs text-neon/60">// what changed</p>
          <p className="text-sm text-cybertext/70 leading-relaxed">
            The NCSC retired Web Check and Mail Check on 31 March 2026, explaining that the commercial
            External Attack Surface Management (EASM) market has matured and that it will only run
            services the market can&apos;t. It published an{" "}
            <a
              href="https://www.ncsc.gov.uk/guidance/external-attack-surface-management-buyers-guide"
              target="_blank"
              rel="noopener noreferrer"
              className="text-neon hover:underline"
            >
              EASM buyer&apos;s guide
            </a>{" "}
            to help organisations choose a replacement (see the NCSC&apos;s own{" "}
            <a
              href="https://www.ncsc.gov.uk/blog-post/retiring-mail-check-web-check"
              target="_blank"
              rel="noopener noreferrer"
              className="text-neon hover:underline"
            >
              retirement notice
            </a>
            ). The NCSC&apos;s free Early Warning service continues, and covers something different —
            alerts about malicious activity and vulnerabilities on your IP addresses. Hebrides Cyber
            is an independent product and is not affiliated with or endorsed by the NCSC.
          </p>
        </div>

        <section aria-labelledby="webcheck-heading" className="mb-14">
          <div className="mb-4">
            <p className="mb-1 font-mono text-xs text-neon/60">// replacing Web Check</p>
            <h2 id="webcheck-heading" className="text-2xl font-bold">
              Your website configuration
            </h2>
            <p className="mt-1 text-sm text-cybertext/60">
              Web Check looked for common website misconfigurations and exposures. Here is how that maps
              to what we scan.
            </p>
          </div>
          <CoverageTable rows={webCheckRows} caption="Web Check coverage mapping" />
        </section>

        <section aria-labelledby="mailcheck-heading" className="mb-14">
          <div className="mb-4">
            <p className="mb-1 font-mono text-xs text-neon/60">// replacing Mail Check</p>
            <h2 id="mailcheck-heading" className="text-2xl font-bold">
              Your email security
            </h2>
            <p className="mt-1 text-sm text-cybertext/60">
              Mail Check checked whether your domain could be spoofed and whether email was sent
              securely. We cover most of it — and we&apos;re honest about the part we don&apos;t yet.
            </p>
          </div>
          <CoverageTable rows={mailCheckRows} caption="Mail Check coverage mapping" />
        </section>

        <div className="mb-14 rounded-lg border border-cyberborder bg-cyberpanel p-6">
          <p className="mb-2 font-mono text-xs text-neon/60">// beyond the retired checks</p>
          <h2 className="mb-3 text-xl font-bold">More than a like-for-like replacement</h2>
          <p className="mb-4 text-sm text-cybertext/70 leading-relaxed">
            The retired services gave you a report. Because we scan on a schedule and keep a history,
            you also get the things a one-off check never could:
          </p>
          <ul className="grid gap-2 text-sm text-cybertext/70 sm:grid-cols-2">
            <li className="flex gap-2">
              <span className="text-neon">→</span> New / fixed comparison between scans, so you see what changed
            </li>
            <li className="flex gap-2">
              <span className="text-neon">→</span> A Security Score and trend over time
            </li>
            <li className="flex gap-2">
              <span className="text-neon">→</span> &quot;Actively exploited&quot; flags from CISA&apos;s KEV catalogue
            </li>
            <li className="flex gap-2">
              <span className="text-neon">→</span> Findings mapped to Cyber Essentials and six other frameworks
            </li>
            <li className="flex gap-2">
              <span className="text-neon">→</span> Alerts to email, Slack or Teams when something new appears
            </li>
            <li className="flex gap-2">
              <span className="text-neon">→</span> A shareable report, plus CSV / JSON export
            </li>
          </ul>
          <p className="mt-4 text-xs text-cybertext/45 leading-relaxed">
            Honest about the gaps: we don&apos;t yet run continuous discovery of unknown assets, and we
            don&apos;t receive DMARC aggregate reports. Both are on our public roadmap. See exactly what
            runs on <Link href="/what-we-check" className="text-neon hover:underline">what we check</Link>.
          </p>
        </div>

        <div className="rounded-xl border border-neon/30 bg-cyberpanel p-8 text-center">
          <p className="mb-1 font-mono text-xs text-neon/60">// get started</p>
          <h2 className="mb-2 text-2xl font-bold">Replace your Web Check today</h2>
          <p className="mx-auto mb-6 max-w-xl text-cybertext/70">
            Run one free scan against a domain you own, no card required. If it&apos;s useful, monitoring
            starts at £20/month — a fraction of what the head-on competitors charge.
          </p>
          <div className="flex flex-wrap justify-center gap-3">
            <Link
              href="/dashboard"
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Run your free scan
            </Link>
            <Link
              href="/contact"
              className="rounded-md border border-cybertext/20 px-6 py-2.5 text-sm font-semibold text-cybertext hover:border-neon hover:text-neon"
            >
              Ask a question
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

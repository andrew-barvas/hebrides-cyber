import Link from "next/link";

// Each service has a primary description, a bullet list of what's included,
// and optional metadata (typical delivery time, who it's for).
type Service = {
  name: string;
  icon: string;
  desc: string;
  includes: string[];
  meta?: string; // e.g. "Delivered within 5 business days"
  tag?: string;  // e.g. "Most popular"
};

const coreServices: Service[] = [
  {
    name: "Web Application Penetration Testing",
    icon: "🔓",
    tag: "Most requested",
    desc: "Manual testing of your web app against the OWASP Top 10 and beyond — authentication, session management, injection, business logic, and API security.",
    includes: [
      "Full OWASP Top 10 coverage (SQLi, XSS, CSRF, IDOR, broken auth…)",
      "API endpoint enumeration and security checks",
      "Business logic review (price manipulation, privilege escalation)",
      "Authenticated and unauthenticated test runs",
      "Written report with reproduction steps, severity ratings, and fix snippets",
      "One free retest of critical/high findings within 30 days",
    ],
    meta: "Report delivered within 5–10 business days",
  },
  {
    name: "CI/CD & DevOps Security Review",
    icon: "⚙️",
    desc: "A full audit of your build pipeline, secrets management, and software supply chain — covering GitHub Actions, container builds, dependency pinning, and deployment config.",
    includes: [
      "GitHub Actions / GitLab CI workflow audit (secret exposure, injection, trigger abuse)",
      "Secrets management review (are keys in env vars, committed to history, over-scoped?)",
      "Dependency pinning and SBOM analysis (known CVEs, unpinned versions)",
      "Container image security scan (base image age, privilege escalation paths)",
      "Deployment and hosting config review (IAM roles, public bucket access, audit logging)",
    ],
    meta: "Initial findings in 3 business days; full report within 7",
  },
  {
    name: "Cloud & Hosting Security Review",
    icon: "☁️",
    desc: "Thorough review of your cloud setup — from Supabase Row-Level Security to S3/Azure Blob bucket policies, IAM roles, and audit log gaps.",
    includes: [
      "Supabase / PostgreSQL RLS policy review",
      "Storage bucket and CDN permissions audit",
      "IAM / service account over-privilege check",
      "API keys and environment variable exposure audit",
      "Audit logging and alerting configuration",
      "Actionable remediation list with copy-paste policy examples",
    ],
    meta: "Delivered within 5 business days",
  },
  {
    name: "Internal Network Assessment",
    icon: "🌐",
    desc: "Lightweight remote network checks for distributed small businesses; partnered on-site engagement available for deeper internal network work across the Highlands and Islands.",
    includes: [
      "External attack surface mapping (open ports, exposed services, leaked credentials)",
      "VPN and remote-access configuration review",
      "On-site available: internal network scan, Wi-Fi segmentation check, device inventory",
      "Firewall rule review",
      "Findings report with remediation priority list",
    ],
    meta: "Remote checks in 3 days; on-site by arrangement",
  },
];

const managedServices: Service[] = [
  {
    name: "Security Score — Automated Scanning",
    icon: "📊",
    tag: "Available now",
    desc: "Weekly automated scans on Basic, daily on Pro and Agency — TLS health, security headers, DNS authentication, exposed paths, and dependency versions — with an AI-generated one-page executive summary emailed to you.",
    includes: [
      "TLS certificate monitoring and expiry alerts",
      "HTTP security header checks (HSTS, CSP, X-Frame-Options, and more)",
      "SPF, DKIM, and DMARC email authentication audit",
      "Sensitive path exposure scan (.env, .git, config files)",
      "Score out of 100 with trend tracking over time",
      "Plain-English AI summary — no jargon",
      "Slack or Microsoft Teams alerts on score change (Pro/Agency plan)",
    ],
    meta: "First scan runs within 24 hours of sign-up",
  },
  {
    name: "Dependency & Patch Monitoring",
    icon: "🔍",
    desc: "Ongoing tracking of outdated libraries, CMS versions, and known CVEs in your dependencies — with remediation PRs opened automatically in your repository when safe fixes are available.",
    includes: [
      "Real dependency scanning (npm, pip, Composer) via OSV.dev, once you connect a repository (Dashboard → Integrations → Connect a repository)",
      "CVE matching against your specific declared dependency versions",
      "Findings tagged new/fixed automatically on every re-scan",
    ],
    meta: "Runs as part of your regular scan cadence (weekly on Basic, daily on Pro/Agency) once a repository is connected",
  },
  {
    name: "Local Business Package",
    icon: "🏪",
    desc: "An all-in-one cyber health check and ongoing support package designed for Highland and Islands small businesses with limited IT resource — covers website, email, backups, and GDPR basics.",
    includes: [
      "One-off website and email security audit",
      "SPF/DKIM/DMARC setup and verification",
      "Google Workspace / Microsoft 365 security settings review",
      "Backup strategy review (3-2-1 rule, recovery test)",
      "GDPR basics: what you need to document and display",
      "60-minute staff security awareness session (remote)",
      "Quarterly check-in call",
    ],
    meta: "Initial audit delivered within 2 weeks",
  },
];

const complianceServices: Service[] = [
  {
    name: "GDPR Readiness Assessment",
    icon: "📋",
    desc: "Practical gap analysis for small teams — identifies what you need to document, what you can defer, and what would cause a regulator the most concern if they knocked on your door today.",
    includes: [
      "Data asset inventory and mapping (what you hold, why, where, for how long)",
      "Lawful basis review for each data processing activity",
      "Privacy notice and cookie banner audit",
      "Subject access request and breach notification process review",
      "Data Protection Impact Assessment (DPIA) for high-risk activities",
      "Policy templates: retention, acceptable use, breach response",
    ],
    meta: "Assessment report in 5 business days",
  },
  {
    name: "Cyber Essentials Preparation",
    icon: "🛡️",
    desc: "Technical and documentation readiness checks aligned to the UK Cyber Essentials scheme — valuable for public sector contracts, grant bids, and supply-chain procurement requirements.",
    includes: [
      "Gap analysis against all five Cyber Essentials control categories",
      "Boundary firewalls and internet gateways review",
      "Secure configuration audit",
      "Access control and administrative privilege review",
      "Patch management and malware protection assessment",
      "Completed self-assessment questionnaire support",
    ],
    meta: "Readiness report within 7 business days; CE+ assessment by arrangement",
  },
  {
    name: "Security Policy & Incident Response Planning",
    icon: "📝",
    desc: "Practical security policies and IR playbooks sized for a small team — not enterprise boilerplate, but documents your staff will actually be able to follow under pressure.",
    includes: [
      "Tailored information security policy (not generic templates)",
      "Incident response runbook: roles, escalation, communication",
      "Tabletop exercise: walk through a realistic attack scenario with your team",
      "Ransomware response checklist",
      "Supplier and third-party risk review process",
      "Annual review built into contract",
    ],
    meta: "Initial policy drafts in 5 business days; tabletop by arrangement",
  },
];

const irServices: Service[] = [
  {
    name: "Incident Response Retainer",
    icon: "🚨",
    desc: "A defined response window and pre-agreed scope so that if something goes wrong, you're not cold-calling a stranger while the clock is ticking.",
    includes: [
      "Named contact with guaranteed response SLA (8 business hours for retainer customers)",
      "Initial triage call within the SLA window",
      "Containment advice and decision support",
      "Evidence preservation guidance (chain of custody, log collection)",
      "Communication support: what to say to customers, regulators, and staff",
      "Post-incident report and lessons-learned session",
    ],
    meta: "Annual or quarterly retainer; by arrangement",
  },
  {
    name: "Remediation Pull Requests",
    icon: "🔧",
    desc: "Findings from a scan or pentest become concrete GitHub PRs — actual code changes your team can review and merge, not just a list of recommendations.",
    includes: [
      "Scan or pentest findings translated into actionable code changes",
      "PRs opened against your repository with explanation comments",
      "Security headers added directly to your config files",
      "Outdated dependencies updated with test results",
      "Your team retains full review and merge control",
      "Available as a follow-on to any Hebrides Cyber assessment",
    ],
    meta: "PRs opened within 3 business days of assessment delivery",
  },
];

const verticals: Service[] = [
  {
    name: "Tourism & Hospitality",
    icon: "🏨",
    desc: "Security for booking systems, point-of-sale, guest Wi-Fi, and GDPR handling across businesses built around seasonal demand and high staff turnover.",
    includes: [
      "Booking system and payment page security review",
      "Guest Wi-Fi segmentation from business network",
      "POS device and card payment security audit",
      "Seasonal staff access management (joiners and leavers)",
      "GDPR: guest data retention and marketing consent",
    ],
  },
  {
    name: "Churches & Charities",
    icon: "⛪",
    desc: "Cost-conscious security support for organisations that hold sensitive pastoral and financial data but rarely have a dedicated IT function.",
    includes: [
      "Donation platform and giving page security review",
      "Charity Commission / OSCR data responsibility audit",
      "Volunteer and staff account management (MFA, shared credentials)",
      "Content archive access control (sermons, safeguarding records)",
      "Budget-conscious recommendations with free-tool alternatives where possible",
    ],
  },
  {
    name: "Crofters & Small Agri-Tech",
    icon: "🌾",
    desc: "IoT device hardening and data security for small agricultural tech operations using remote sensors, telemetry, or grant-funded digital tools.",
    includes: [
      "IoT device inventory and firmware version audit",
      "Remote access (SSH, VPN, web interfaces) security check",
      "Agricultural data platform review (who can access sensor data)",
      "Grant compliance: data handling requirements for AgriTech funding",
    ],
  },
  {
    name: "Photography & Creative Businesses",
    icon: "📷",
    desc: "Security for client galleries, watermarking workflows, and checkout pages — protecting both creative assets and customer payment data.",
    includes: [
      "Client gallery access control and link expiry review",
      "Checkout and payment security for print/product sales",
      "Cloud storage (Dropbox, Google Drive, OneDrive) sharing audit",
      "Copyright and watermark workflow security",
      "Backup and disaster recovery for image archives",
    ],
  },
];

type ServiceCardProps = Service & { expanded?: boolean };

function ServiceCard({ name, icon, desc, includes, meta, tag }: ServiceCardProps) {
  return (
    <div className="group relative rounded-lg border border-cyberborder bg-cyberpanel p-5 transition duration-200 hover:border-neon/50 hover:shadow-glowsm flex flex-col">
      <div className="mb-3 flex items-start gap-3">
        <span className="text-xl flex-shrink-0 mt-0.5">{icon}</span>
        <div className="flex-1">
          <div className="flex items-start justify-between gap-2">
            <h3 className="font-mono text-sm font-semibold text-neon leading-snug">{name}</h3>
            {tag && (
              <span className="flex-shrink-0 rounded-full bg-neon/10 px-2 py-0.5 text-xs font-medium text-neon border border-neon/20">
                {tag}
              </span>
            )}
          </div>
          <p className="mt-1.5 text-sm text-cybertext/70 leading-relaxed">{desc}</p>
        </div>
      </div>

      <ul className="mt-3 space-y-1.5 flex-1">
        {includes.map((item) => (
          <li key={item} className="flex items-start gap-2 text-xs text-cybertext/60">
            <span className="flex-shrink-0 mt-0.5 text-neon/50">›</span>
            <span>{item}</span>
          </li>
        ))}
      </ul>

      {meta && (
        <p className="mt-4 pt-3 border-t border-cyberborder text-xs text-cybertext/60 font-mono">
          ⏱ {meta}
        </p>
      )}
    </div>
  );
}

function Section({ label, title, subtitle, items }: { label: string; title: string; subtitle?: string; items: Service[] }) {
  return (
    <section className="mb-16">
      <div className="mb-5 flex items-center gap-3" aria-hidden="true">
        <span className="font-mono text-xs text-neon/60">{label}</span>
        <div className="h-px flex-1 bg-cyberborder" />
      </div>
      <h2 className="mb-1 text-xl font-bold text-cybertext">{title}</h2>
      {subtitle && <p className="mb-5 text-sm text-cybertext/50">{subtitle}</p>}
      <div className="grid gap-4 sm:grid-cols-2">
        {items.map((s) => <ServiceCard key={s.name} {...s} />)}
      </div>
    </section>
  );
}

export default function ServicesPage() {
  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      {/* Hero */}
      <div className="relative overflow-hidden border-b border-cyberborder px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> ls ./services <span className="text-cybertext/60">|</span> grep --all
          </p>
          <h1 className="mx-auto max-w-2xl text-4xl font-bold sm:text-5xl">
            What we do
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-cybertext/70">
            From an automated weekly Security Score to hands-on penetration testing and incident response —
            sized and priced for businesses that don&apos;t have a full-time security team.
          </p>
          <p className="mt-3 text-sm text-cybertext/50">
            Fixed rates on the{" "}
            <Link href="/pricing" className="text-neon underline underline-offset-2 hover:text-cybertext">
              pricing page
            </Link>
            {" "}· full technical check list on{" "}
            <Link href="/what-we-check" className="text-neon underline underline-offset-2 hover:text-cybertext">
              what we check
            </Link>
            {" "}· bespoke quotes via{" "}
            <Link href="/contact" className="text-neon underline underline-offset-2 hover:text-cybertext">
              contact
            </Link>
          </p>
        </div>
      </div>

      {/* How it works — three steps */}
      <div className="border-b border-cyberborder bg-cyberpanel/30 px-6 py-10">
        <div className="mx-auto max-w-4xl">
          <h2 className="sr-only">How it works</h2>
          <p className="mb-6 font-mono text-xs text-neon/60 text-center" aria-hidden="true">// how it works</p>
          <div className="grid gap-6 sm:grid-cols-3 text-center">
            {[
              { step: "01", title: "Book a free scan", body: "Run our automated Security Score against your site. Get a one-page report in 24 hours, no commitment." },
              { step: "02", title: "Review the findings", body: "We explain every finding in plain English — no jargon, no scare tactics. You decide what to fix first." },
              { step: "03", title: "We fix it or you do", body: "Ongoing monitoring keeps the score up. Or we can open PRs and fix findings directly in your codebase." },
            ].map(({ step, title, body }) => (
              <div key={step} className="relative">
                <div aria-hidden="true" className="mb-3 inline-block font-mono text-3xl font-bold text-neon/20">{step}</div>
                <p className="mb-1 font-semibold text-cybertext text-sm">{title}</p>
                <p className="text-xs text-cybertext/60 leading-relaxed">{body}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Service groups */}
      <div className="mx-auto max-w-4xl px-6 py-16">
        <Section
          label="// 01"
          title="Core Assurance"
          subtitle="One-off assessments with written reports, CVSS severity ratings, and a guaranteed retest on critical findings."
          items={coreServices}
        />
        <Section
          label="// 02"
          title="Continuous & Managed"
          subtitle="Ongoing protection that runs in the background — useful for businesses that want monitoring without hiring a security team."
          items={managedServices}
        />
        <Section
          label="// 03"
          title="Compliance & Governance"
          subtitle="Practical documentation and readiness work for businesses navigating GDPR, Cyber Essentials, or procurement requirements."
          items={complianceServices}
        />
        <Section
          label="// 04"
          title="Incident Response & Remediation"
          subtitle="Support when something has gone wrong, and concrete code fixes when you want findings turned into pull requests."
          items={irServices}
        />
        <Section
          label="// 05"
          title="Hebrides Verticals"
          subtitle="Sector-specific packages for businesses across the Highlands and Islands where generic advice often doesn't fit."
          items={verticals}
        />

        {/* CTA */}
        <div className="rounded-xl border border-neon/30 bg-cyberpanel p-8 text-center">
          <p className="mb-1 font-mono text-xs text-neon/60">// ready?</p>
          <h2 className="mb-2 text-2xl font-bold">Not sure where to start?</h2>
          <p className="mb-6 text-cybertext/70">
            Book a free Security Score scan — get a one-page report in 24 hours, no commitment.
            Or just{" "}
            <Link href="/contact" className="text-neon underline hover:text-cybertext">get in touch</Link>{" "}
            and we&apos;ll recommend the right starting point.
          </p>
          <div className="flex flex-wrap justify-center gap-3">
            <Link
              href="/dashboard"
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Run a free scan
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
    </div>
  );
}

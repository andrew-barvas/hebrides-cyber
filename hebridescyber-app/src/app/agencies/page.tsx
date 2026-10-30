import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "For Agencies & MSPs — Hebrides Cyber",
  description:
    "White-label security scanning for digital agencies. Monitor up to 15 client sites with a fleet overview, per-site scan profiles, branded PDF reports and one-click ticketing — from £75/month.",
};

type Capability = {
  icon: string;
  title: string;
  body: string;
};

// Every entry here must describe something a paying Agency customer can use
// today — this page is the sales pitch for a £75/mo plan. Planned work goes
// in `roadmap` below, clearly labelled, and moves up only once it ships.
const capabilities: Capability[] = [
  {
    icon: "📊",
    title: "Fleet overview",
    body: "See every client site at a glance: latest score, trend, open findings and last scan date. Worst scores surface first so you catch problems before your clients do.",
  },
  {
    icon: "🎨",
    title: "White-label PDF reports",
    body: "Upload your logo and company name, and every PDF Security Score report you send carries your brand, not ours.",
  },
  {
    icon: "📋",
    title: "Per-site scan profiles",
    body: "Different clients need different check suites. Pick a profile for each site — from a safe passive baseline to full, API- or CMS-focused active suites — and daily scheduled scans run the right tools for it.",
  },
  {
    icon: "🔗",
    title: "Ticketing integrations",
    body: "Send a finding to Jira, Linear, ServiceNow or GitHub Issues in one click. Tickets are de-duplicated per finding, and can close themselves when a later scan confirms the fix.",
  },
  {
    icon: "📈",
    title: "Compliance mapping & export",
    body: "Every finding is mapped to ISO 27001, PCI DSS, Cyber Essentials, OWASP Top 10, CIS Controls v8, NIS2, DORA, SOC 2 and HIPAA. Download any scan as a per-framework control report (Markdown, CSV or JSON) for a client's audit pack, labelled as an automated indicator rather than a certification.",
  },
  {
    icon: "⏱️",
    title: "Remediation SLAs",
    body: "Set fix-by targets per severity and see every open finding's deadline across your client sites, with median time-to-fix and an email before a site breaches. A passive re-scan never counts as a fix for something only the active tools can see.",
  },
  {
    icon: "📧",
    title: "Scheduled reports",
    body: "Daily, weekly or monthly security summaries sent to your team or straight to clients, with CSV and JSON exports for your own reporting tools.",
  },
];

const roadmap: Capability[] = [
  {
    icon: "🏢",
    title: "MSP partner portal",
    body: "Onboard clients and give each one access to only their own sites and reports.",
  },
];

const pricingFeatures = [
  "Up to 15 client sites",
  "Daily scheduled scans",
  "Fleet overview dashboard",
  "White-label PDF reports",
  "Per-site scan profiles",
  "Priority email support",
  "Findings mapped to 7 compliance frameworks, with per-framework report export",
  "Jira, Linear, ServiceNow & GitHub Issues ticketing",
  "Scheduled report delivery",
  "Portfolio PDF: every client site in one report, worst first",
  "Remediation SLAs with breach alerts",
  "SBOM generation (CycloneDX 1.5)",
  "CI templates for GitHub Actions, GitLab, Jenkins, Azure DevOps & Bitbucket",
];

function CapabilityCard({ capability }: { capability: Capability }) {
  return (
    <div className="rounded-lg border border-cyberborder bg-cyberpanel p-5 transition duration-200 hover:border-neon/50 hover:shadow-glowsm">
      <div className="mb-3 flex items-start gap-3">
        <span className="text-xl shrink-0 mt-0.5">{capability.icon}</span>
        <div>
          <h3 className="font-mono text-sm font-semibold text-neon leading-snug">{capability.title}</h3>
          <p className="mt-1.5 text-sm text-cybertext/70 leading-relaxed">{capability.body}</p>
        </div>
      </div>
    </div>
  );
}

export default function AgenciesPage() {
  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      <div className="relative overflow-hidden border-b border-cyberborder px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> fleet status --clients=all --sort=score
          </p>
          <h1 className="mx-auto max-w-2xl text-4xl font-bold sm:text-5xl">
            Security scanning for agencies and MSPs
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-cybertext/70">
            Monitor your clients&apos; sites from one platform. White-label reports, fleet-wide
            visibility and compliance-mapped findings — without building it yourself.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <Link
              href="/pricing"
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Agency plan — £75/mo
            </Link>
            <Link
              href="/contact"
              className="rounded-md border border-cybertext/20 px-6 py-2.5 text-sm font-semibold text-cybertext hover:border-neon hover:text-neon"
            >
              Book a demo
            </Link>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-4xl px-6 py-16">
        <div className="mb-8">
          <p className="mb-1 font-mono text-xs text-neon/60">// the problem</p>
          <p className="text-sm text-cybertext/60 leading-relaxed">
            You look after a portfolio of client websites. Each one needs security monitoring, but
            you can&apos;t run a separate tool per site, and your clients expect branded reports —
            not a forwarded email from a tool they&apos;ve never heard of. The Agency tier covers up
            to 15 client sites from one dashboard and one scan pipeline, with reports that carry
            your brand. Looking after more than that?{" "}
            <Link href="/contact" className="text-neon hover:underline">
              Talk to us
            </Link>
            .
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          {capabilities.map((c) => (
            <CapabilityCard key={c.title} capability={c} />
          ))}
        </div>

        <div className="mt-16">
          <p className="mb-1 font-mono text-xs text-neon/60">// on the roadmap</p>
          <h2 className="mb-2 text-2xl font-bold">Coming to the Agency plan</h2>
          <p className="mb-6 text-sm text-cybertext/60">
            Not available yet — listed so you know where the plan is heading.
          </p>
          <div className="grid gap-4 sm:grid-cols-2">
            {roadmap.map((c) => (
              <div key={c.title} className="rounded-lg border border-dashed border-cyberborder p-5">
                <div className="flex items-start gap-3">
                  <span className="mt-0.5 shrink-0 text-xl opacity-70" aria-hidden="true">
                    {c.icon}
                  </span>
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="font-mono text-sm font-semibold text-cybertext">{c.title}</h3>
                      <span className="rounded-full border border-cyberborder px-2 py-0.5 text-[11px] font-medium text-cybermuted">
                        Coming soon
                      </span>
                    </div>
                    <p className="mt-1.5 text-sm leading-relaxed text-cybertext/70">{c.body}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="mt-16 rounded-xl border border-cyberborder bg-cyberpanel p-8">
          <h2 className="mb-4 text-center text-2xl font-bold">Everything in the Agency plan</h2>
          <div className="grid gap-2 sm:grid-cols-2">
            {pricingFeatures.map((f) => (
              <div key={f} className="flex items-center gap-2 text-sm text-cybertext/70">
                <span className="text-neon shrink-0">✓</span>
                {f}
              </div>
            ))}
          </div>
          <div className="mt-6 text-center">
            <Link
              href="/pricing"
              className="inline-block rounded-md bg-neon px-8 py-3 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Start your Agency plan
            </Link>
          </div>
        </div>

        <div className="mt-16 rounded-xl border border-neon/30 bg-cyberpanel p-8 text-center">
          <p className="mb-1 font-mono text-xs text-neon/60">// resell security under your brand</p>
          <h2 className="mb-2 text-2xl font-bold">White-label security as a service</h2>
          <p className="mb-6 text-cybertext/70">
            Your clients see your brand on the security reports you send them. Add scanning as a
            line item in your existing retainer — or build a standalone security offering on top
            of our infrastructure.
          </p>
          <div className="flex flex-wrap justify-center gap-3">
            <Link
              href="/dashboard"
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Try it free
            </Link>
            <Link
              href="/contact"
              className="rounded-md border border-cybertext/20 px-6 py-2.5 text-sm font-semibold text-cybertext hover:border-neon hover:text-neon"
            >
              Discuss partnership
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

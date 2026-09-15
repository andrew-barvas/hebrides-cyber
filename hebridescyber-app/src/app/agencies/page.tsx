import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "For Agencies & MSPs — Hebrides Cyber",
  description:
    "White-label security scanning for digital agencies and managed service providers. Fleet overview, custom scan policies, SLA monitoring, and branded PDF reports from £75/month.",
};

type Capability = {
  icon: string;
  title: string;
  body: string;
};

const capabilities: Capability[] = [
  {
    icon: "🏢",
    title: "MSP partner portal",
    body: "Manage all client sites from one dashboard. Onboard clients, assign scan policies, and monitor SLA compliance without switching accounts. Full multi-tenant isolation — each client sees only their own data.",
  },
  {
    icon: "📊",
    title: "Fleet overview",
    body: "See every client site at a glance: score, trend sparkline, open findings count, and last scan date. Worst scores surface first so you catch problems before your clients do.",
  },
  {
    icon: "🎨",
    title: "White-label reports",
    body: "PDF and web reports carry your brand, not ours. Upload your logo, set your company name, and deliver branded Security Score reports your clients associate with your service.",
  },
  {
    icon: "📋",
    title: "Custom scan policies",
    body: "Different clients need different check suites. Create reusable scan policies — which checks to run, severity thresholds, scan windows — and assign them per client or per site.",
  },
  {
    icon: "⏱️",
    title: "SLA monitoring",
    body: "Set response-time targets per severity. Track mean time to remediate across your client portfolio. Get alerted when a site is at risk of breaching its SLA — not after.",
  },
  {
    icon: "🔗",
    title: "Ticketing integrations",
    body: "Route findings directly to your team's workflow — Jira, Linear, ServiceNow, or GitHub Issues. One-click ticket creation with automatic deduplication and auto-close when findings are resolved.",
  },
  {
    icon: "📈",
    title: "Compliance across 7 frameworks",
    body: "Every finding is mapped to ISO 27001, PCI DSS, Cyber Essentials, OWASP Top 10, CIS Controls v8, NIS2, and DORA. Generate compliance-ready reports for client audits without extra work.",
  },
  {
    icon: "📧",
    title: "Scheduled reports",
    body: "Automated daily, weekly, or monthly security summaries sent to your team or directly to clients. CSV and JSON formats for integration with your existing reporting tools.",
  },
];

const pricingFeatures = [
  "Unlimited client sites",
  "Fleet overview dashboard",
  "White-label PDF reports",
  "Custom scan policies",
  "SLA monitoring",
  "MSP partner portal",
  "Priority email support",
  "All 7 compliance frameworks",
  "Jira / Linear / ServiceNow integration",
  "Scheduled report delivery",
  "SBOM generation (CycloneDX 1.5)",
  "CI/CD SDK + GitHub Action",
];

function CapabilityCard({ capability }: { capability: Capability }) {
  return (
    <div className="rounded-lg border border-cyberborder bg-cyberpanel p-5 transition duration-200 hover:border-neon/50 hover:shadow-glowsm">
      <div className="mb-3 flex items-start gap-3">
        <span className="text-xl flex-shrink-0 mt-0.5">{capability.icon}</span>
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
            Manage security across your entire client portfolio from one platform. White-label
            reports, fleet-wide visibility, and automated compliance — without building it yourself.
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
            You manage 10, 50, or 200 client websites. Each one needs security monitoring, but
            you can&apos;t run a separate tool per site, and your clients expect branded reports —
            not a forwarded email from a tool they&apos;ve never heard of. Hebrides Cyber&apos;s Agency
            tier gives you one dashboard for every client, one scan pipeline for every site, and
            reports that carry your brand.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          {capabilities.map((c) => (
            <CapabilityCard key={c.title} capability={c} />
          ))}
        </div>

        <div className="mt-16 rounded-xl border border-cyberborder bg-cyberpanel p-8">
          <h2 className="mb-4 text-center text-2xl font-bold">Everything in the Agency plan</h2>
          <div className="grid gap-2 sm:grid-cols-2">
            {pricingFeatures.map((f) => (
              <div key={f} className="flex items-center gap-2 text-sm text-cybertext/70">
                <span className="text-neon flex-shrink-0">✓</span>
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
            Your clients see your brand on every report, every email, and every dashboard.
            Add security scanning as a line item in your existing retainer — or build a
            standalone security offering on top of our infrastructure.
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

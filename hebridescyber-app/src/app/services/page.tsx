import Link from "next/link";

const coreServices = [
  { name: "Web Application Penetration Testing", icon: "🔓", desc: "OWASP Top 10 manual testing, API security, auth/session checks, business logic review." },
  { name: "CI/CD & DevOps Security", icon: "⚙️", desc: "GitHub Actions review, secrets management, supply-chain risk analysis." },
  { name: "Cloud & Hosting Reviews", icon: "☁️", desc: "Supabase RLS, storage bucket permissions, IAM roles, audit logging." },
  { name: "Internal Network Assessment", icon: "🌐", desc: "Lightweight remote network checks for small businesses; partnered on-site work for deeper engagements." },
];

const managedServices = [
  { name: "Security Score (SaaS)", icon: "📊", desc: "Automated weekly/monthly scans — TLS, headers, dependencies, open ports — with an AI-generated executive summary." },
  { name: "Dependency & Patch Monitoring", icon: "🔍", desc: "Ongoing tracking of outdated libraries and CMS versions, with remediation PRs opened automatically." },
  { name: "Local Business Package", icon: "🏪", desc: "Website security, email authentication (SPF/DKIM/DMARC), backups, GDPR basics, staff training." },
];

const complianceServices = [
  { name: "GDPR Readiness", icon: "📋", desc: "Gap analysis, DPIAs, and policy templates for small teams without a dedicated compliance function." },
  { name: "Cyber Essentials Preparation", icon: "🛡️", desc: "Documentation and technical checks aligned to the UK Cyber Essentials scheme — useful for procurement bids." },
  { name: "Security Policy & IR Planning", icon: "📝", desc: "Tabletop exercises, runbooks, and incident response playbooks tailored to a small team's real capacity." },
];

const irServices = [
  { name: "Incident Response Retainer", icon: "🚨", desc: "A defined response window, triage, and containment support — scoped for what a local business can realistically use." },
  { name: "Remediation Pull Requests", icon: "🔧", desc: "Findings from a scan become a real GitHub PR with concrete fix snippets — reviewed and merged by your own team." },
];

const verticals = [
  { name: "Tourism & Hospitality", icon: "🏨", desc: "Booking systems, POS, guest Wi-Fi segmentation, and GDPR handling for guest data." },
  { name: "Churches & Charities", icon: "⛪", desc: "Donation platform security, sermon archive access control, volunteer account management." },
  { name: "Crofters & Small Agri-Tech", icon: "🌾", desc: "IoT device hardening and telemetry security for small-scale agricultural tech." },
  { name: "Photography & Creative Businesses", icon: "📷", desc: "Secure galleries, watermarking workflows, and checkout security for print sales." },
];

type ServiceGroup = { name: string; icon: string; desc: string };

function ServiceCard({ name, icon, desc }: ServiceGroup) {
  return (
    <div className="group relative rounded-lg border border-cyberborder bg-cyberpanel p-5 transition duration-200 hover:border-neon/50 hover:shadow-glowsm">
      <div className="mb-3 flex items-center gap-3">
        <span className="text-xl">{icon}</span>
        <h3 className="font-mono text-sm font-semibold text-neon">{name}</h3>
      </div>
      <p className="text-sm text-slatelight/70 leading-relaxed">{desc}</p>
    </div>
  );
}

function Section({ label, title, items }: { label: string; title: string; items: ServiceGroup[] }) {
  return (
    <section className="mb-14">
      <div className="mb-5 flex items-center gap-3">
        <span className="font-mono text-xs text-neon/60">{label}</span>
        <div className="h-px flex-1 bg-cyberborder" />
      </div>
      <h2 className="mb-5 text-xl font-bold text-white">{title}</h2>
      <div className="grid gap-4 sm:grid-cols-2">
        {items.map((s) => <ServiceCard key={s.name} {...s} />)}
      </div>
    </section>
  );
}

export default function ServicesPage() {
  return (
    <div className="bg-cyberbg min-h-screen text-white">
      {/* Hero */}
      <div className="relative overflow-hidden border-b border-cyberborder px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon">
            <span className="text-slatelight/30">$</span> ls ./services <span className="text-slatelight/30">|</span> grep --all
          </p>
          <h1 className="mx-auto max-w-2xl text-4xl font-bold sm:text-5xl">
            What we do
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-slatelight/70">
            From an automated weekly Security Score to hands-on penetration testing and incident response.
            Packaged rates on the{" "}
            <Link href="/pricing" className="text-neon underline underline-offset-2 hover:text-white">
              pricing page
            </Link>
            , or{" "}
            <Link href="/contact" className="text-neon underline underline-offset-2 hover:text-white">
              get in touch
            </Link>{" "}
            for a scoped quote.
          </p>
        </div>
      </div>

      {/* Service groups */}
      <div className="mx-auto max-w-4xl px-6 py-16">
        <Section label="// 01" title="Core Assurance" items={coreServices} />
        <Section label="// 02" title="Continuous & Managed" items={managedServices} />
        <Section label="// 03" title="Compliance & Governance" items={complianceServices} />
        <Section label="// 04" title="Incident Response & Remediation" items={irServices} />
        <Section label="// 05" title="Hebrides Verticals" items={verticals} />

        {/* CTA */}
        <div className="rounded-xl border border-neon/30 bg-cyberpanel p-8 text-center">
          <p className="mb-1 font-mono text-xs text-neon/60">// ready?</p>
          <h2 className="mb-2 text-2xl font-bold">Not sure where to start?</h2>
          <p className="mb-6 text-slatelight/70">Book a free Security Score scan — get a one-page report in 24 hours, no commitment.</p>
          <div className="flex flex-wrap justify-center gap-3">
            <Link
              href="/contact"
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Book a free scan
            </Link>
            <Link
              href="/pricing"
              className="rounded-md border border-white/20 px-6 py-2.5 text-sm font-semibold text-white hover:border-neon hover:text-neon"
            >
              View pricing
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

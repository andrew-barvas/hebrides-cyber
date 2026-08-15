// Expanded from the competitor services catalogue —
// marketing/09-competitor-services-catalogue.md — grouped the same way:
// core assurance, continuous/managed, compliance, incident response,
// developer add-ons, and Hebrides-specific verticals. Keep the two in
// sync if you edit one.

const coreServices = [
  { name: "Web Application Penetration Testing", desc: "OWASP Top 10 manual testing, API security, auth/session checks, business logic review." },
  { name: "CI/CD & DevOps Security", desc: "GitHub Actions review, secrets management, supply-chain risk analysis." },
  { name: "Cloud & Hosting Reviews", desc: "Supabase RLS, storage bucket permissions, IAM roles, audit logging." },
  { name: "Internal Network Assessment", desc: "Lightweight remote network checks for small businesses; partnered on-site work for deeper engagements." },
];

const managedServices = [
  { name: "Security Score (SaaS)", desc: "Automated weekly/monthly scans — TLS, headers, dependencies, open ports, headless page load — with an AI-generated executive summary." },
  { name: "Dependency & Patch Monitoring", desc: "Ongoing tracking of outdated libraries and CMS versions, with remediation PRs (see below) opened automatically." },
  { name: "Local Business Package", desc: "Website security, email authentication (SPF/DKIM/DMARC), backups, GDPR basics, staff training." },
];

const complianceServices = [
  { name: "GDPR Readiness", desc: "Gap analysis, DPIAs, and policy templates for small teams without a dedicated compliance function." },
  { name: "Cyber Essentials Preparation", desc: "Documentation and technical checks aligned to the UK Cyber Essentials scheme — useful for procurement bids." },
  { name: "Security Policy & IR Planning", desc: "Tabletop exercises, runbooks, and incident response playbooks tailored to a small team's real capacity." },
];

const irServices = [
  { name: "Incident Response Retainer", desc: "A defined response window, triage, and containment support — scoped for what a local business can realistically use, not enterprise SOC pricing." },
  { name: "Remediation Pull Requests", desc: "Findings from a scan become a real GitHub PR with concrete fix snippets — reviewed and merged by your own team, never a silent auto-change to production." },
];

const verticals = [
  { name: "Tourism & Hospitality", desc: "Booking systems, POS, guest Wi-Fi segmentation, and GDPR handling for guest data." },
  { name: "Churches & Charities", desc: "Donation platform security, sermon archive access control, volunteer account management." },
  { name: "Crofters & Small Agri-Tech", desc: "IoT device hardening and telemetry security for small-scale agricultural tech." },
  { name: "Photography & Creative Businesses", desc: "Secure galleries, watermarking workflows, and checkout security for print sales." },
];

function ServiceGroup({ title, items }: { title: string; items: Array<{ name: string; desc: string }> }) {
  return (
    <section className="mb-12">
      <h2 className="mb-4 text-xl font-semibold text-atlantic">{title}</h2>
      <div className="space-y-4">
        {items.map((s) => (
          <div key={s.name} className="rounded-lg border border-slate-200 p-5">
            <h3 className="font-semibold">{s.name}</h3>
            <p className="mt-1 text-sm text-slatedark/80">{s.desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

export default function ServicesPage() {
  return (
    <div className="mx-auto max-w-4xl px-6 py-16">
      <p className="mb-1 font-mono text-xs text-atlantic/60">// services.list()</p>
      <h1 className="mb-2 text-3xl font-bold text-atlantic">Services</h1>
      <p className="mb-10 text-slatedark/80">
        From an automated weekly Security Score to hands-on penetration
        testing and incident response — see{" "}
        <a href="/pricing" className="underline">
          pricing
        </a>{" "}
        for packaged rates, or get in touch for a scoped quote.
      </p>

      <ServiceGroup title="Core Assurance" items={coreServices} />
      <ServiceGroup title="Continuous & Managed" items={managedServices} />
      <ServiceGroup title="Compliance & Governance" items={complianceServices} />
      <ServiceGroup title="Incident Response & Remediation" items={irServices} />
      <ServiceGroup title="Hebrides Verticals" items={verticals} />
    </div>
  );
}

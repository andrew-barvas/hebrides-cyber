import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Security for Churches & Charities — Hebrides Cyber",
  description:
    "Cost-conscious security scanning for Highland and Islands churches and charities — donation pages, email impersonation, and volunteer access explained without the jargon.",
};

// Concerns are framed around the real Security Score scan (see
// src/app/what-we-check/page.tsx for the full technical checklist) — no
// vertical-specific scanning technology exists, this page just explains the
// same checks in terms that matter to a church or charity.
type Concern = {
  icon: string;
  title: string;
  scope: "Automated" | "Manual / advisory";
  body: string;
};

const concerns: Concern[] = [
  {
    icon: "💝",
    title: "Giving and donation pages",
    scope: "Automated",
    body: "Whether donations run through an embedded widget, a link to a giving platform, or your own form, the scan checks the page serving it enforces HTTPS properly, has no mixed content warnings, and carries sane security headers — the basic hygiene a donor's browser is quietly checking too.",
  },
  {
    icon: "✉️",
    title: "Impersonation of the church or charity by email",
    scope: "Automated",
    body: "A fake urgent appeal \"from the treasurer\" or \"from the minister\" asking for an emergency transfer is one of the most common scams charities face. SPF, DKIM, and DMARC on your domain are what stop someone spoofing your email address to send it — checked on every scan.",
  },
  {
    icon: "🧱",
    title: "Old CMS versions and exposed files",
    scope: "Automated",
    body: "Many church and charity sites are built once, by a volunteer, on WordPress or a similar platform, and rarely updated after. The scan fingerprints outdated CMS/plugin versions and probes for leftover config files, debug logs, and backup archives left behind by old migrations.",
  },
  {
    icon: "🎙️",
    title: "Sermon archives and safeguarding records",
    scope: "Manual / advisory",
    body: "Who can actually open the shared Google Drive or Dropbox folder holding sermon recordings or safeguarding files isn't something a website scan can see. That's a settings and permissions review, not an automated check — we cover it as part of a Local Business Package review.",
  },
  {
    icon: "🔑",
    title: "Volunteer and shared account access",
    scope: "Manual / advisory",
    body: "Volunteers come and go, and shared logins that never get rotated are a common, quiet risk. It's a process question rather than something visible from outside your site, so it's advisory guidance rather than an automated finding.",
  },
];

function ConcernCard({ concern }: { concern: Concern }) {
  return (
    <div className="group relative rounded-lg border border-cyberborder bg-cyberpanel p-5 transition duration-200 hover:border-neon/50 hover:shadow-glowsm flex flex-col">
      <div className="mb-3 flex items-start gap-3">
        <span className="text-xl shrink-0 mt-0.5">{concern.icon}</span>
        <div className="flex-1">
          <div className="flex items-start justify-between gap-2">
            <h3 className="font-mono text-sm font-semibold text-neon leading-snug">{concern.title}</h3>
            <span
              className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-medium border ${
                concern.scope === "Automated"
                  ? "bg-neon/10 text-neon border-neon/20"
                  : "bg-cybertext/5 text-cybertext/60 border-cybertext/20"
              }`}
            >
              {concern.scope}
            </span>
          </div>
          <p className="mt-1.5 text-sm text-cybertext/70 leading-relaxed">{concern.body}</p>
        </div>
      </div>
    </div>
  );
}

export default function ChurchesPage() {
  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      {/* Hero */}
      <div className="relative overflow-hidden border-b border-cyberborder px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> scan --target=giving-page --budget=charity
          </p>
          <h1 className="mx-auto max-w-2xl text-4xl font-bold sm:text-5xl">
            Security for churches and charities that hold real trust
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-cybertext/70">
            You handle donations, pastoral records, and safeguarding data, usually without a dedicated IT
            person and always on a tight budget. Here&apos;s what an automated scan catches for free, and
            what genuinely needs a human.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
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

      <div className="mx-auto max-w-4xl px-6 py-16">
        <div className="mb-8">
          <p className="mb-1 font-mono text-xs text-neon/60">// why this matters for churches &amp; charities</p>
          <p className="text-sm text-cybertext/60 leading-relaxed">
            Trust is the whole point — donors, congregation members, and volunteers give you their money and
            their details because they believe you&apos;ll look after them. A spoofed appeal email or an
            exposed donor list undoes that trust fast, and most churches and charities simply don&apos;t have
            the budget for enterprise security tooling. The automated scan is built to be affordable first.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          {concerns.map((c) => (
            <ConcernCard key={c.title} concern={c} />
          ))}
        </div>

        <p className="mt-6 text-xs text-cybertext/50">
          Every &ldquo;Automated&rdquo; item above runs as part of the standard Security Score scan — see the{" "}
          <Link href="/what-we-check" className="text-neon underline hover:text-cybertext">
            full technical checklist
          </Link>
          . &ldquo;Manual / advisory&rdquo; items are covered as part of our{" "}
          <Link href="/services" className="text-neon underline hover:text-cybertext">
            Local Business Package and GDPR Readiness Assessment
          </Link>
          , priced to be realistic for a charity budget.
        </p>

        {/* CTA */}
        <div className="mt-16 rounded-xl border border-neon/30 bg-cyberpanel p-8 text-center">
          <p className="mb-1 font-mono text-xs text-neon/60">// ready?</p>
          <h2 className="mb-2 text-2xl font-bold">See where your site and email stand, at no cost</h2>
          <p className="mb-6 text-cybertext/70">
            Free automated scan, one-page report in 24 hours, no commitment. Ongoing monitoring starts at
            £20/month if you want it kept up to date.
          </p>
          <div className="flex flex-wrap justify-center gap-3">
            <Link
              href="/dashboard"
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Run a free scan
            </Link>
            <Link
              href="/contact"
              className="rounded-md border border-cybertext/20 px-6 py-2.5 text-sm font-semibold text-cybertext hover:border-neon hover:text-neon"
            >
              Ask a question first
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

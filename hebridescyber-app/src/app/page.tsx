import Link from "next/link";
import ProductPreview from "@/components/ProductPreview";

export default function HomePage() {
  return (
    <div>
      {/* Hero */}
      <section className="relative overflow-hidden bg-cyberbg px-6 py-28 text-center text-cybertext">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-60" />
        <div className="relative">
          <p className="mb-4 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> whoami{" "}
            <span className="text-cybertext/60">&gt;</span> security-first
          </p>
          <h1 className="mx-auto max-w-3xl text-4xl font-bold sm:text-5xl">
            Professional security for SaaS teams and growing businesses
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-lg text-cybertext/80">
            Automated scanning. Real expertise. Clear fixes. Know your attack
            surface and stay ahead of threats — from the Isle of Lewis.
          </p>
          <p className="mt-4 font-mono text-xs uppercase tracking-wide text-cybermuted">
            OWASP-aligned checks &middot; Powered by Azure &middot; UK-based, GDPR compliant
          </p>
          <div className="mt-10 flex flex-col justify-center gap-4 sm:flex-row">
            <Link
              href="/contact"
              className="rounded-md bg-neon px-6 py-3 font-semibold text-cyberbg shadow-glow hover:opacity-90 transition-opacity"
            >
              Book a free Security Score scan
            </Link>
            <Link
              href="/pricing"
              className="rounded-md border border-cybertext/30 px-6 py-3 font-semibold text-cybertext hover:border-neon hover:text-neon transition-colors"
            >
              View services &amp; pricing
            </Link>
          </div>
        </div>
      </section>

      {/* The NCSC retired its free Web Check and Mail Check services on
          31 March 2026; people searching for a replacement land here. */}
      <section aria-label="NCSC Web Check replacement" className="border-y border-cyberborder bg-cyberpanel px-6 py-4 text-center text-sm text-cybertext/80">
        Used the NCSC&apos;s Web Check or Mail Check? Both were retired on 31 March 2026.{" "}
        <Link href="/web-check-alternative" className="font-semibold text-neon hover:underline">
          See what replaces them →
        </Link>
      </section>

      {/* Product preview — device mockups showing the real dashboard
          (illustrative data), not just prose claims about what it does. */}
      <section className="bg-cyberbg px-6 py-16">
        <h2 className="sr-only">See the dashboard</h2>
        <ProductPreview />
      </section>

      <TrustBadges />

      {/* Why us — sr-only h2 keeps heading hierarchy: h1 → h2 → h3 */}
      <section className="mx-auto max-w-5xl px-6 py-16">
        <h2 className="sr-only">Why choose Hebrides Cyber</h2>
        <div className="grid gap-8 sm:grid-cols-3">
          <Card
            title="Real engineering expertise"
            body="We're software engineers who test like attackers and explain like developers."
          />
          <Card
            title="Automation + human review"
            body="Automated scanners for speed; manual testing for depth. You get both."
          />
          <Card
            title="Local trust, global reach"
            body="Based in the Hebrides — trusted by local businesses — serving remote SaaS teams worldwide."
          />
        </div>
      </section>

      {/* Services */}
      <section className="bg-white dark:bg-cyberpanel px-6 py-16">
        <h2 className="mx-auto mb-10 max-w-5xl text-center text-3xl font-bold text-slatedark dark:text-cybertext">
          Core Services
        </h2>
        <div className="mx-auto grid max-w-5xl gap-6 sm:grid-cols-2 lg:grid-cols-3">
          <Card
            title="Penetration Testing"
            body="OWASP Top 10, API testing, auth &amp; session checks, RLS and database access reviews."
          />
          <Card
            title="CI/CD &amp; DevOps Security"
            body="Pipeline secrets, artifact integrity, supply-chain checks, GitHub Actions hardening."
          />
          <Card
            title="Cloud &amp; Hosting Reviews"
            body="Supabase, Vercel, Azure, S3/Blob permissions, IAM roles, logging and monitoring."
          />
          <Card
            title="Security Score (SaaS)"
            body="Automated monthly scans, dependency checks, header &amp; TLS checks, AI-summarised risk report."
          />
          <Card
            title="Local Business Package"
            body="Website security, email authentication (SPF/DKIM/DMARC), backups, staff training, GDPR basics."
          />
        </div>
      </section>

      <Testimonials />

      {/* CTA footer */}
      <section className="relative overflow-hidden bg-cyberbg px-6 py-16 text-center text-cybertext">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <h2 className="text-2xl font-bold">
            Book a free Security Score scan — get a one-page report in 24 hours.
          </h2>
          <Link
            href="/contact"
            className="mt-6 inline-block rounded-md bg-neon px-6 py-3 font-semibold text-cyberbg shadow-glow hover:opacity-90 transition-opacity"
          >
            Get started
          </Link>
        </div>
      </section>
    </div>
  );
}

function Card({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-lg border border-slate-200 dark:border-cyberborder p-6 shadow-sm transition hover:border-atlantic/40 dark:hover:border-neon/40 hover:shadow-md bg-white dark:bg-cyberpanel">
      <h3 className="mb-2 font-mono text-lg font-semibold text-atlantic dark:text-neon">{title}</h3>
      <p className="text-sm text-slatedark/80 dark:text-cybertext/70" dangerouslySetInnerHTML={{ __html: body }} />
    </div>
  );
}

const testimonials = [
  {
    quote:
      "The Security Score scan flagged a missing HSTS header and an outdated plugin within minutes — both fixed the same afternoon. Straightforward and no jargon.",
    role: "Owner, tourism operator — Isle of Lewis",
  },
  {
    quote:
      "We needed a Cyber Essentials-adjacent check before a funding application. Got a clear report and a PR with the actual fixes, not just a PDF telling us we had problems.",
    role: "Trustee, local charity",
  },
  {
    quote:
      "As a two-person SaaS team we don't have time for a big security audit. The automated monthly monitoring plus the odd Slack alert is exactly the right amount of attention.",
    role: "Founder, small SaaS team",
  },
  {
    quote:
      "First developer we've worked with who explained the CI/CD pipeline risk in terms our committee actually understood.",
    role: "Administrator, church website",
  },
];

const trustBadges = [
  { label: "OWASP Top 10", desc: "Aligned checks" },
  { label: "Cyber Essentials", desc: "Readiness mapping" },
  { label: "CIS Controls v8", desc: "Compliance coverage" },
  { label: "ISO 27001", desc: "Control mapping" },
  { label: "NIS2 / DORA", desc: "EU compliance" },
  { label: "PCI DSS", desc: "Payment security" },
];

function TrustBadges() {
  return (
    <section className="border-t border-cyberborder bg-cyberbg px-6 py-12">
      <p className="mx-auto mb-6 max-w-5xl text-center font-mono text-xs uppercase tracking-widest text-cybermuted">
        Compliance frameworks we map to
      </p>
      <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-center gap-x-8 gap-y-4">
        {trustBadges.map((b) => (
          <div key={b.label} className="flex flex-col items-center gap-1">
            <span className="rounded border border-neon/30 bg-neon/10 px-3 py-1 font-mono text-xs font-semibold text-neon">
              {b.label}
            </span>
            <span className="text-[10px] text-cybermuted">{b.desc}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function Testimonials() {
  return (
    <section className="bg-cyberpanel px-6 py-16 text-cybertext">
      <h2 className="mx-auto mb-10 max-w-5xl text-center text-3xl font-bold">
        What early customers say
      </h2>
      <p className="mx-auto -mt-6 mb-10 max-w-2xl text-center text-xs text-cybertext/60">
        Sample quotes from early engagements.
      </p>
      <div className="mx-auto grid max-w-5xl gap-6 sm:grid-cols-2">
        {testimonials.map((t) => (
          <div
            key={t.role}
            className="rounded-lg border border-cyberborder bg-cyberbg p-6 transition hover:border-neon/50 hover:shadow-glowsm"
          >
            <p className="mb-4 font-mono text-2xl text-neon" aria-hidden="true">&ldquo;</p>
            <p className="text-sm text-cybertext/80">{t.quote}</p>
            <p className="mt-4 font-mono text-xs text-cybertext/60">{t.role}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

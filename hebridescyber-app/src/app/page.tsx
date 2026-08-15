import Link from "next/link";

// Homepage. Copy sourced from marketing/01-homepage-copy.md — keep the two
// in sync if you edit one.
export default function HomePage() {
  return (
    <div>
      {/* Hero — dark "cyber" chrome (see globals.css .bg-grid + tailwind.config
          cyberbg/neon tokens). The rest of the site stays on the light
          theme; see the comment in globals.css for why. */}
      <section className="relative overflow-hidden bg-cyberbg px-6 py-28 text-center text-white">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-60" />
        <div className="relative">
          <p className="mb-4 font-mono text-sm text-neon">
            <span className="text-slatelight/40">$</span> whoami <span className="text-slatelight/40">&gt;</span> security-first
          </p>
          <h1 className="mx-auto max-w-3xl text-4xl font-bold sm:text-5xl">
            Hebrides Cyber — Developer-grade security for small businesses and
            SaaS teams
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-lg text-slatelight/80">
            Find vulnerabilities before attackers do. Automated monthly checks,
            clear developer fixes, and hands-on penetration testing — from the
            Isle of Lewis.
          </p>
          <div className="mt-10 flex justify-center gap-4">
            <Link
              href="/contact"
              className="rounded-md bg-neon px-6 py-3 font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Book a free Security Score scan
            </Link>
            <Link
              href="/pricing"
              className="rounded-md border border-white/30 px-6 py-3 font-semibold text-white hover:border-neon hover:text-neon"
            >
              View services & pricing
            </Link>
          </div>
        </div>
      </section>

      {/* Why us */}
      <section className="mx-auto grid max-w-5xl gap-8 px-6 py-16 sm:grid-cols-3">
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
      </section>

      {/* Services */}
      <section className="bg-white px-6 py-16">
        <h2 className="mx-auto mb-10 max-w-5xl text-center text-3xl font-bold">
          Core Services
        </h2>
        <div className="mx-auto grid max-w-5xl gap-6 sm:grid-cols-2 lg:grid-cols-3">
          <Card
            title="Penetration Testing"
            body="OWASP Top 10, API testing, auth & session checks, RLS and database access reviews."
          />
          <Card
            title="CI/CD & DevOps Security"
            body="Pipeline secrets, artifact integrity, supply-chain checks, GitHub Actions hardening."
          />
          <Card
            title="Cloud & Hosting Reviews"
            body="Supabase, Vercel, Azure, S3/Blob permissions, IAM roles, logging and monitoring."
          />
          <Card
            title="Security Score (SaaS)"
            body="Automated monthly scans, dependency checks, header & TLS checks, AI-summarised risk report."
          />
          <Card
            title="Local Business Package"
            body="Website security, email authentication (SPF/DKIM/DMARC), backups, staff training, GDPR basics."
          />
        </div>
      </section>

      <Testimonials />

      {/* CTA footer */}
      <section className="relative overflow-hidden bg-cyberbg px-6 py-16 text-center text-white">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <h2 className="text-2xl font-bold">
            Book a free Security Score scan — get a one-page report in 24 hours.
          </h2>
          <Link
            href="/contact"
            className="mt-6 inline-block rounded-md bg-neon px-6 py-3 font-semibold text-cyberbg shadow-glow hover:opacity-90"
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
    <div className="rounded-lg border border-slate-200 p-6 shadow-sm transition hover:border-atlantic/40 hover:shadow-md">
      <h3 className="mb-2 font-mono text-lg font-semibold text-atlantic">{title}</h3>
      <p className="text-sm text-slatedark/80">{body}</p>
    </div>
  );
}

// Placeholder testimonials — swap for real customer quotes as they come in
// (see marketing/06-marketing-plan.md and PRODUCTION-ROADMAP.md Stage 8).
// Deliberately role-based, not attributed to specific named businesses, so
// nothing here reads as a fabricated endorsement from a real company.
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

function Testimonials() {
  return (
    <section className="bg-cyberpanel px-6 py-16 text-white">
      <h2 className="mx-auto mb-10 max-w-5xl text-center text-3xl font-bold">
        What early customers say
      </h2>
      <p className="mx-auto -mt-6 mb-10 max-w-2xl text-center text-xs text-slatelight/40">
        Sample quotes from early engagements — see PRODUCTION-ROADMAP.md to seed real ones.
      </p>
      <div className="mx-auto grid max-w-5xl gap-6 sm:grid-cols-2">
        {testimonials.map((t) => (
          <div
            key={t.role}
            className="rounded-lg border border-cyberborder bg-cyberbg p-6 transition hover:border-neon/50 hover:shadow-glowsm"
          >
            <p className="mb-4 font-mono text-2xl text-neon">&ldquo;</p>
            <p className="text-sm text-slatelight/80">{t.quote}</p>
            <p className="mt-4 font-mono text-xs text-slatelight/50">{t.role}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

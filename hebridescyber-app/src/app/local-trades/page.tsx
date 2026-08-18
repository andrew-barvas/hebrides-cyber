import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Security for Local Trades — Hebrides Cyber",
  description:
    "Plain-English security scanning for Highland and Islands electricians, plumbers, joiners, and small retailers — quote forms, invoice fraud, and Google Business Profile hygiene, with no IT department required.",
};

// Concerns are framed around the real Security Score scan (see
// src/app/what-we-check/page.tsx for the full technical checklist) — no
// vertical-specific scanning technology exists, this page just explains the
// same checks in terms that matter to a local trades business.
type Concern = {
  icon: string;
  title: string;
  scope: "Automated" | "Manual / advisory";
  body: string;
};

const concerns: Concern[] = [
  {
    icon: "🧾",
    title: "Quote requests, contact forms, and deposits",
    scope: "Automated",
    body: "If customers submit a contact form, request a quote, or pay a deposit through your site, the scan checks that page enforces HTTPS properly, has no mixed-content issues, and carries the cookie and header protections that keep that form submission from being tampered with in transit.",
  },
  {
    icon: "✉️",
    title: "Invoice fraud and email impersonation",
    scope: "Automated",
    body: "\"Please pay this invoice to our new account details\" scams specifically target trades businesses, because customers expect an invoice email from you mid-job. SPF, DKIM, and DMARC on your domain are what stop someone spoofing your address to send one — checked on every scan.",
  },
  {
    icon: "🧱",
    title: "An old website nobody's touched in years",
    scope: "Automated",
    body: "A lot of trades sites were built once by a local web designer and haven't been opened since. The scan fingerprints your CMS and plugin versions (WordPress, Wix, Squarespace, whatever it is) and flags outdated software plus any leftover config or backup files a forgotten migration left exposed.",
  },
  {
    icon: "📍",
    title: "Google Business Profile and listing accounts",
    scope: "Manual / advisory",
    body: "Your Google Business Profile, Facebook page, and directory listings live outside your own website, so a site scan can't check them — but a shared or reused password on one of those accounts is a real, common way small trades businesses get their listing hijacked. This is advisory guidance, not an automated finding.",
  },
  {
    icon: "🧑‍🔧",
    title: "No dedicated IT person",
    scope: "Manual / advisory",
    body: "You're running the business, not a helpdesk. That's exactly what the automated scan is for — an outside check you don't have to remember to do — with our Local Business Package available if you'd rather someone just tell you what to fix and set up email authentication for you.",
  },
];

function ConcernCard({ concern }: { concern: Concern }) {
  return (
    <div className="group relative rounded-lg border border-cyberborder bg-cyberpanel p-5 transition duration-200 hover:border-neon/50 hover:shadow-glowsm flex flex-col">
      <div className="mb-3 flex items-start gap-3">
        <span className="text-xl flex-shrink-0 mt-0.5">{concern.icon}</span>
        <div className="flex-1">
          <div className="flex items-start justify-between gap-2">
            <h3 className="font-mono text-sm font-semibold text-neon leading-snug">{concern.title}</h3>
            <span
              className={`flex-shrink-0 rounded-full px-2 py-0.5 text-xs font-medium border ${
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

export default function LocalTradesPage() {
  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      {/* Hero */}
      <div className="relative overflow-hidden border-b border-cyberborder px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> scan --target=quote-site --it-team=none
          </p>
          <h1 className="mx-auto max-w-2xl text-4xl font-bold sm:text-5xl">
            Security for electricians, joiners, plumbers, and small shops
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-cybertext/70">
            You&apos;ve got a booking or quote website, maybe you take deposits online, and definitely no time
            to think about security software. Here&apos;s what an automated scan checks in the background,
            and what&apos;s worth a quick manual look.
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
          <p className="mb-1 font-mono text-xs text-neon/60">// why this matters for local trades</p>
          <p className="text-sm text-cybertext/60 leading-relaxed">
            Most local trades businesses don&apos;t run anything more complex than a website with a quote form
            and an inbox full of job details and invoices — which is exactly why they&apos;re a soft target for
            scams that don&apos;t need a technical exploit, just a spoofed email or a hijacked listing. The
            automated scan is built for a business with no IT department: run it, get a plain-English
            report, fix what matters.
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
            Local Business Package
          </Link>
          , which is built specifically for businesses without a dedicated IT resource.
        </p>

        {/* CTA */}
        <div className="mt-16 rounded-xl border border-neon/30 bg-cyberpanel p-8 text-center">
          <p className="mb-1 font-mono text-xs text-neon/60">// ready?</p>
          <h2 className="mb-2 text-2xl font-bold">Find out where your site stands, for free</h2>
          <p className="mb-6 text-cybertext/70">
            Free automated scan, one-page report in 24 hours, no commitment. Ongoing monitoring from
            £20/month, or a one-off Small Website Audit from £300 if you&apos;d rather it was done once and done
            properly.
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

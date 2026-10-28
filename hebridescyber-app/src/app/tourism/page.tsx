import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Security for Tourism & Hospitality — Hebrides Cyber",
  description:
    "Automated security scanning for Highland and Islands guesthouses, hotels, and self-catering businesses — booking systems, guest email authentication, and seasonal-site checks explained in plain English.",
};

// Concerns are framed around the real Security Score scan (see
// src/app/what-we-check/page.tsx for the full technical checklist) — no
// vertical-specific scanning technology exists, this page just explains the
// same checks in terms that matter to a tourism operator.
type Concern = {
  icon: string;
  title: string;
  scope: "Automated" | "Manual / advisory";
  body: string;
};

const concerns: Concern[] = [
  {
    icon: "📅",
    title: "Booking and payment pages",
    scope: "Automated",
    body: "Whatever you use — a plugin bolted onto WordPress, a third-party widget, or a bespoke booking form — the scan checks TLS is actually enforced, the certificate isn't close to expiry mid-season, and the security headers around that page (cookie flags, HSTS, CSP) are set correctly.",
  },
  {
    icon: "✉️",
    title: "Guest confirmation emails and impersonation",
    scope: "Automated",
    body: "SPF, DKIM, and DMARC on your domain determine whether someone can send a convincing fake booking confirmation or payment-details email pretending to be you. This is checked on every scan and is one of the highest-value, lowest-effort fixes we see.",
  },
  {
    icon: "🧱",
    title: "Old plugins and forgotten config files",
    scope: "Automated",
    body: "A lot of Hebridean B&B and self-catering sites are WordPress sites set up once and rarely touched. The scan fingerprints outdated plugin/CMS versions and probes for the specific files (.env, wp-config.php.bak, debug logs) that a rushed migration leaves exposed.",
  },
  {
    icon: "📶",
    title: "Guest Wi-Fi segmentation and POS devices",
    scope: "Manual / advisory",
    body: "Whether your guest network is actually isolated from the till and the office PC isn't something a website scan can see — it needs a look at your router and network setup. This falls under our Internal Network Assessment, not the automated Security Score.",
  },
  {
    icon: "👥",
    title: "Seasonal staff access",
    scope: "Manual / advisory",
    body: "Shared logins and accounts that never get switched off after the season ends are a real, common gap — but it's a process question, not something visible from outside your site. We cover this as part of a Local Business Package review, not the automated scan.",
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

export default function TourismPage() {
  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      {/* Hero */}
      <div className="relative overflow-hidden border-b border-cyberborder px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> scan --target=booking-site --season=summer
          </p>
          <h1 className="mx-auto max-w-2xl text-4xl font-bold sm:text-5xl">
            Security for guesthouses, hotels, and self-catering
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-cybertext/70">
            Your booking system, guest data, and email are exposed to the same internet as everyone
            else&apos;s — but you don&apos;t have a full season to spend chasing it down. Here&apos;s what an
            automated scan catches, and what still needs a human.
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
          <p className="mb-1 font-mono text-xs text-neon/60">// why this matters for tourism</p>
          <p className="text-sm text-cybertext/60 leading-relaxed">
            Seasonal demand means your site gets a burst of bookings and card payments in a short window,
            often with the least staff time available to check anything is actually secure. Guests hand
            over names, addresses, and card details expecting that to be handled properly — and one bad
            headline about a leaked booking database travels fast in a small community.
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
          . &ldquo;Manual / advisory&rdquo; items need a person, not a scanner — they&apos;re part of our{" "}
          <Link href="/services" className="text-neon underline hover:text-cybertext">
            Local Business Package and Internal Network Assessment
          </Link>
          .
        </p>

        {/* CTA */}
        <div className="mt-16 rounded-xl border border-neon/30 bg-cyberpanel p-8 text-center">
          <p className="mb-1 font-mono text-xs text-neon/60">// ready?</p>
          <h2 className="mb-2 text-2xl font-bold">Get a Security Score before your next season starts</h2>
          <p className="mb-6 text-cybertext/70">
            Free automated scan, one-page report in 24 hours, no commitment. Ongoing monitoring from £20/month
            once you&apos;re ready.
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

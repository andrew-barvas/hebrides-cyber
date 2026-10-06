import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Cyber Essentials readiness scan — Hebrides Cyber",
  description:
    "Check your website and internet-facing services against the five Cyber Essentials controls before you apply. An automated indicator, mapped control by control.",
};

type Control = {
  name: string;
  /** What an external scan can genuinely show for this control. */
  weCheck: string;
  /** What only your own self-assessment can answer. */
  youAnswer: string;
};

// Kept in step with the Cyber Essentials rows in src/lib/scanners/compliance.ts:
// each "weCheck" names checks that are mapped to that control there. An
// external scan sees only what faces the internet, so every control also says
// what it cannot see.
const controls: Control[] = [
  {
    name: "Firewalls and internet gateways",
    weCheck: "Services exposed to the internet that shouldn't be: open database, remote-desktop and admin ports on your site's addresses.",
    youAnswer: "Firewall rules on your office network and on every device, including home workers' routers.",
  },
  {
    name: "Secure configuration",
    weCheck: "TLS and certificates, security headers, cookie flags, exposed files and directory listings, error pages that leak detail, and email and DNS records (SPF, DMARC, MTA-STS, CAA).",
    youAnswer: "How laptops, phones and servers are configured: default passwords removed, unused software and accounts disabled, auto-run off.",
  },
  {
    name: "Security update management",
    weCheck: "Software your site reveals that is out of date or end of life, matched to known vulnerabilities, with CISA's list of actively exploited ones flagged first.",
    youAnswer: "Whether every device and application is licensed, supported and patched within 14 days of a high-risk update.",
  },
  {
    name: "User access control",
    weCheck: "Data or admin functions reachable without signing in: open databases and storage behind your site (Supabase, Firebase), exposed keys, user enumeration, missing login rate limits.",
    youAnswer: "Who has accounts and admin rights, multi-factor authentication for staff and cloud services, and how leavers are removed.",
  },
  {
    name: "Malware protection",
    weCheck: "Whether Google Safe Browsing flags your site as distributing malware or phishing.",
    youAnswer: "Anti-malware or application allow-listing on every device in scope.",
  },
];

export default function CyberEssentialsPage() {
  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      <div className="relative overflow-hidden border-b border-cyberborder px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> ./readiness --framework cyber-essentials
          </p>
          <h1 className="mx-auto max-w-3xl text-4xl font-bold sm:text-5xl">Cyber Essentials readiness scan</h1>
          <p className="mx-auto mt-4 max-w-2xl text-cybertext/70">
            Find the problems an assessor or an attacker would see on your website and internet-facing services, before
            you apply. Every finding is mapped to the Cyber Essentials control it affects, with a plain-English fix.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <Link
              href="/dashboard"
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Run your free scan
            </Link>
            <Link
              href="/sample-reports"
              className="rounded-md border border-cybertext/20 px-6 py-2.5 text-sm font-semibold text-cybertext hover:border-neon hover:text-neon"
            >
              See a sample report
            </Link>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-4xl px-6 py-16">
        <div className="mb-12 rounded-lg border border-cyberborder bg-cyberpanel p-6">
          <p className="mb-2 font-mono text-xs text-neon/60">// what this is, and isn&apos;t</p>
          <p className="text-sm leading-relaxed text-cybertext/70">
            Cyber Essentials is the UK government-backed scheme, run by IASME for the NCSC, that certifies five basic
            technical controls. Certification is a self-assessment questionnaire, and Cyber Essentials Plus adds a hands-on
            technical audit. Our scan is an <strong className="text-cybertext">automated indicator</strong> for the part of
            those controls that faces the internet: it helps you find and fix problems before you apply, but it is not a
            certification and doesn&apos;t replace the questionnaire. Hebrides Cyber is independent and is not a
            certification body.
          </p>
        </div>

        <section aria-labelledby="controls-heading" className="mb-14">
          <p className="mb-1 font-mono text-xs text-neon/60">// the five controls</p>
          <h2 id="controls-heading" className="mb-2 text-2xl font-bold">
            What a scan can show, and what only you can answer
          </h2>
          <p className="mb-6 text-sm text-cybertext/60">
            A scan sees your systems from the outside. For each control, this is the part we check and the part your own
            self-assessment has to cover.
          </p>
          <div className="space-y-4">
            {controls.map((c) => (
              <article key={c.name} className="rounded-lg border border-cyberborder bg-cyberpanel p-5">
                <h3 className="mb-3 text-lg font-semibold">{c.name}</h3>
                <dl className="grid gap-3 text-sm sm:grid-cols-2">
                  <div>
                    <dt className="mb-1 font-mono text-xs text-neon">We check</dt>
                    <dd className="text-cybertext/75">{c.weCheck}</dd>
                  </div>
                  <div>
                    <dt className="mb-1 font-mono text-xs text-cybertext/50">You answer</dt>
                    <dd className="text-cybertext/60">{c.youAnswer}</dd>
                  </div>
                </dl>
              </article>
            ))}
          </div>
        </section>

        <div className="mb-14 rounded-lg border border-cyberborder bg-cyberpanel p-6">
          <p className="mb-2 font-mono text-xs text-neon/60">// in every report</p>
          <h2 className="mb-3 text-xl font-bold">Findings grouped by control</h2>
          <ul className="grid gap-2 text-sm text-cybertext/70 sm:grid-cols-2">
            <li className="flex gap-2">
              <span className="text-neon">→</span> A Cyber Essentials breakdown on every scan report
            </li>
            <li className="flex gap-2">
              <span className="text-neon">→</span> A compliance report to download (CSV through the API)
            </li>
            <li className="flex gap-2">
              <span className="text-neon">→</span> A step-by-step fix for each finding
            </li>
            <li className="flex gap-2">
              <span className="text-neon">→</span> Rescans that show what you&apos;ve fixed since last time
            </li>
          </ul>
          <p className="mt-4 text-xs leading-relaxed text-cybertext/45">
            The same findings are also mapped to ISO 27001, PCI DSS, NIS2, DORA, OWASP Top 10 and CIS Controls. If you used
            the NCSC&apos;s retired Web Check or Mail Check, see{" "}
            <Link href="/web-check-alternative" className="text-neon hover:underline">
              how we cover them
            </Link>
            .
          </p>
        </div>

        <div className="rounded-xl border border-neon/30 bg-cyberpanel p-8 text-center">
          <p className="mb-1 font-mono text-xs text-neon/60">// get started</p>
          <h2 className="mb-2 text-2xl font-bold">Check before you apply</h2>
          <p className="mx-auto mb-6 max-w-xl text-cybertext/70">
            Run one free scan against a domain you own, no card required. Monitoring that rescans on a schedule starts at
            £20/month.
          </p>
          <div className="flex flex-wrap justify-center gap-3">
            <Link
              href="/dashboard"
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Run your free scan
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

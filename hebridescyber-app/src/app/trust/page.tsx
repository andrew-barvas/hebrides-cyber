import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Trust — Hebrides Cyber",
  description:
    "What security controls Hebrides Cyber runs today, who processes your data, and a plain statement that we are not yet SOC 2 or ISO 27001 certified.",
};

const LAST_UPDATED = "October 2026";
const CONTACT_EMAIL = "hello@hebridescyber.co.uk";

const CONTROLS = [
  "Row Level Security isolates each customer's data in the database, with automated tests that run against a real Postgres in CI.",
  "A Content-Security-Policy with a fresh per-request nonce, plus HSTS and other browser security headers.",
  "Stored third-party secrets (for example tracker tokens and cloud credentials you give us) are encrypted at rest with AES-256-GCM.",
  "Optional two-factor sign-in (authenticator app) for every account.",
  "Scans only run against domains you have proved you control.",
  "An audit log records security-relevant actions.",
  "Rate limiting on the API.",
  "Our own dependencies are audited for known vulnerabilities on every dependency change and weekly, and Dependabot proposes updates.",
  "Changes go through automated lint, type, unit, end-to-end and database tests, and database migrations are tracked and checked for drift before each release.",
  "Customer data is deleted on request, and scan results and report PDFs are removed after the retention periods in the privacy policy.",
  "Database backups are provided by our database host; a written restore procedure is kept in our repository.",
];

const SUBPROCESSORS = [
  { name: "Supabase", purpose: "Database and authentication (EU region)" },
  { name: "Microsoft Azure", purpose: "Hosting, compute and blob storage" },
  { name: "Stripe", purpose: "Payment processing" },
  { name: "Resend", purpose: "Transactional email" },
  { name: "Sentry", purpose: "Error monitoring" },
  { name: "Google Analytics", purpose: "Usage analytics, only with your consent" },
];

export default function TrustPage() {
  return (
    <div className="bg-slatelight dark:bg-cyberbg min-h-screen">
      <div className="relative mx-auto max-w-3xl px-6 py-16">
        <Link
          href="/"
          className="mb-8 inline-block font-mono text-xs text-slatedark/50 hover:text-atlantic dark:text-cybermuted dark:hover:text-neon transition-colors"
        >
          ← Back to home
        </Link>

        <div className="mb-10">
          <p className="font-mono text-xs text-neon mb-2" aria-hidden="true">// trust.md</p>
          <h1 className="text-3xl font-bold text-slatedark dark:text-cybertext">Trust</h1>
          <p className="mt-2 text-sm text-slatedark/50 dark:text-cybermuted">Last updated: {LAST_UPDATED}</p>
        </div>

        <div className="prose prose-slate max-w-none dark:prose-invert dark:prose-headings:text-neon dark:prose-a:text-neon dark:prose-strong:text-cybertext">
          <h2>Certification status</h2>
          <p>
            <strong>Hebrides Cyber is not SOC 2 attested and not ISO 27001 certified.</strong> We have not been
            audited against either standard. We are doing the groundwork so that an audit is possible, and we will
            update this page only when an independent auditor has said so.
          </p>

          <h2>Controls in place today</h2>
          <p>These are things we run now, not promises. They are not a substitute for an independent assessment.</p>
          <ul>
            {CONTROLS.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>

          <h2>Sub-processors</h2>
          <p>
            These providers process personal data on our behalf. The privacy policy has the full detail, including
            international transfers.
          </p>
          <table>
            <thead>
              <tr><th>Provider</th><th>Purpose</th></tr>
            </thead>
            <tbody>
              {SUBPROCESSORS.map((s) => (
                <tr key={s.name}><td>{s.name}</td><td>{s.purpose}</td></tr>
              ))}
            </tbody>
          </table>

          <h2>Security contact</h2>
          <p>
            To report a suspected vulnerability in Hebrides Cyber itself, email{" "}
            <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a> or use the{" "}
            <Link href="/contact">contact form</Link>. Please do not post exploitable details publicly. Our{" "}
            <a href="/.well-known/security.txt">security.txt</a> lists the same contacts.
          </p>

          <h2>Related</h2>
          <ul>
            <li><Link href="/privacy">Privacy Policy</Link></li>
            <li><Link href="/terms">Terms of Service</Link></li>
          </ul>
        </div>
      </div>
    </div>
  );
}

import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Privacy Policy — Hebrides Cyber",
  description: "How Hebrides Cyber collects, uses, and protects your personal data.",
};

const LAST_UPDATED = "August 2025";
const CONTACT_EMAIL = "hello@hebridescyber.com";
const COMPANY = "Hebrides Cyber";
const COMPANY_LOCATION = "Isle of Lewis, Scotland, UK";

export default function PrivacyPage() {
  return (
    <div className="bg-slatelight dark:bg-cyberbg min-h-screen">
      <div className="bg-grid pointer-events-none fixed inset-0 opacity-0 dark:opacity-20" />

      <div className="relative mx-auto max-w-3xl px-6 py-16">
        <Link
          href="/"
          className="mb-8 inline-block font-mono text-xs text-slatedark/50 hover:text-atlantic dark:text-white/40 dark:hover:text-neon transition-colors"
        >
          ← Back to home
        </Link>

        <div className="mb-10">
          <p className="font-mono text-xs text-neon mb-2" aria-hidden="true">// privacy-policy.md</p>
          <h1 className="text-3xl font-bold text-slatedark dark:text-white">Privacy Policy</h1>
          <p className="mt-2 text-sm text-slatedark/50 dark:text-white/40">Last updated: {LAST_UPDATED}</p>
        </div>

        <div className="prose prose-slate max-w-none dark:prose-invert dark:prose-headings:text-neon dark:prose-a:text-neon dark:prose-strong:text-white dark:prose-code:text-neon dark:prose-code:bg-cyberpanel">
          <h2>1. Who we are</h2>
          <p>
            {COMPANY} (&ldquo;we&rdquo;, &ldquo;us&rdquo;, &ldquo;our&rdquo;) provides automated security scanning,
            penetration testing advisory, and CI/CD hardening services. We are based in the {COMPANY_LOCATION}.
            For data protection purposes we act as the <strong>data controller</strong> of the personal data
            we collect via this website.
          </p>
          <p>
            Questions about this policy: <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>
          </p>

          <h2>2. What data we collect</h2>
          <h3>2a. Account data</h3>
          <p>When you sign up or sign in we collect:</p>
          <ul>
            <li>Email address (used for authentication and service communications)</li>
            <li>Full name and company name (optional, entered in your profile)</li>
            <li>Authentication metadata (sign-in timestamps, MFA enrolment) managed by Supabase Auth</li>
          </ul>

          <h3>2b. Scan data</h3>
          <p>
            When you run a security scan we record the target URL, scan results (TLS grade, header findings,
            DNS records, exposed paths, vulnerability findings), a computed score, and an AI-generated summary.
            <strong> Scan targets must be domains you own or are authorised to test</strong> — by submitting
            a scan you confirm this.
          </p>

          <h3>2c. Contact enquiries</h3>
          <p>
            If you use the contact form we store your name, email address, website URL (if provided), and
            your message. We use this to respond to your enquiry.
          </p>

          <h3>2d. Subscription and billing</h3>
          <p>
            Subscription status and plan tier are stored in our database. Payment card details are
            handled entirely by <a href="https://stripe.com/gb/privacy" target="_blank" rel="noreferrer">Stripe</a>;
            we never see or store full card numbers.
          </p>

          <h3>2e. Usage analytics</h3>
          <p>
            We use Google Analytics 4 to understand how the site is used (page views, session duration).
            Analytics cookies are only set after you accept the cookie consent banner. You can opt out
            at any time by withdrawing consent (click &ldquo;Cookie settings&rdquo; in the site footer).
          </p>

          <h3>2f. Server logs</h3>
          <p>
            Our hosting provider (Microsoft Azure) retains standard server access logs (IP address, request
            path, timestamp, HTTP status) for up to 30 days for security and operational purposes.
          </p>

          <h2>3. Why we process your data (legal basis)</h2>
          <table>
            <thead>
              <tr><th>Data</th><th>Purpose</th><th>Lawful basis</th></tr>
            </thead>
            <tbody>
              <tr><td>Account &amp; authentication</td><td>Providing the service</td><td>Contract</td></tr>
              <tr><td>Scan data</td><td>Delivering scan results and reports</td><td>Contract</td></tr>
              <tr><td>Contact enquiries</td><td>Responding to your enquiry</td><td>Legitimate interests</td></tr>
              <tr><td>Billing</td><td>Processing subscription payments</td><td>Contract</td></tr>
              <tr><td>Analytics</td><td>Improving the site</td><td>Consent</td></tr>
              <tr><td>Server logs</td><td>Security and operations</td><td>Legitimate interests</td></tr>
            </tbody>
          </table>

          <h2>4. Who we share data with</h2>
          <p>We do not sell personal data. We share data with the following service providers:</p>
          <ul>
            <li><strong>Supabase</strong> — database and authentication (hosted in EU region)</li>
            <li><strong>Stripe</strong> — payment processing</li>
            <li><strong>Microsoft Azure</strong> — hosting, compute, and blob storage</li>
            <li><strong>Google Analytics</strong> — usage analytics (only with your consent)</li>
            <li><strong>Resend</strong> — transactional email (contact form notifications)</li>
          </ul>
          <p>All processors are bound by data processing agreements and process data only on our instructions.</p>

          <h2>5. International transfers</h2>
          <p>
            Some of our processors operate outside the UK/EEA. Where data is transferred internationally
            we rely on standard contractual clauses or adequacy decisions in place between the UK and
            the relevant countries to ensure equivalent protection.
          </p>

          <h2>6. How long we keep data</h2>
          <ul>
            <li><strong>Account data:</strong> for as long as your account is active, then deleted within 30 days of account closure.</li>
            <li><strong>Scan results:</strong> retained for 12 months then purged automatically.</li>
            <li><strong>Contact enquiries:</strong> retained for 12 months, then deleted.</li>
            <li><strong>PDF reports</strong> stored in Azure Blob Storage: deleted after 90 days.</li>
            <li><strong>Server logs:</strong> up to 30 days.</li>
          </ul>

          <h2>7. Your rights</h2>
          <p>Under UK GDPR you have the right to:</p>
          <ul>
            <li><strong>Access</strong> the personal data we hold about you</li>
            <li><strong>Correct</strong> inaccurate data</li>
            <li><strong>Erase</strong> your data (&ldquo;right to be forgotten&rdquo;) where no overriding legal obligation requires us to keep it</li>
            <li><strong>Restrict</strong> processing in certain circumstances</li>
            <li><strong>Data portability</strong> — receive a copy of your data in a structured, machine-readable format</li>
            <li><strong>Object</strong> to processing based on legitimate interests</li>
            <li><strong>Withdraw consent</strong> for analytics at any time without affecting prior processing</li>
          </ul>
          <p>
            To exercise any of these rights, email <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>.
            We will respond within 30 days. You also have the right to lodge a complaint with the
            UK&apos;s supervisory authority, the{" "}
            <a href="https://ico.org.uk" target="_blank" rel="noreferrer">Information Commissioner&apos;s Office (ICO)</a>.
          </p>

          <h2>8. Cookies</h2>
          <p>We use the following cookies:</p>
          <table>
            <thead>
              <tr><th>Cookie</th><th>Purpose</th><th>Duration</th><th>Consent required</th></tr>
            </thead>
            <tbody>
              <tr><td><code>hc-theme</code></td><td>Saves your light/dark theme preference</td><td>1 year</td><td>No (functional)</td></tr>
              <tr><td><code>hc-cookie-consent</code></td><td>Records your cookie consent choice</td><td>1 year</td><td>No (functional)</td></tr>
              <tr><td>Supabase auth cookies</td><td>Maintains your signed-in session</td><td>Session / 7 days</td><td>No (essential)</td></tr>
              <tr><td>Google Analytics (<code>_ga</code>, <code>_gid</code>)</td><td>Usage analytics</td><td>Up to 2 years</td><td>Yes</td></tr>
            </tbody>
          </table>

          <h2>9. Security</h2>
          <p>
            We apply TLS encryption in transit, row-level security on all database tables, and
            regular automated security scanning against our own infrastructure. Sensitive credentials
            are stored as environment variables, never in source code. Despite these measures, no
            system is completely secure — if you believe you&apos;ve found a vulnerability in our
            platform, please disclose it responsibly to <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>.
          </p>

          <h2>10. Changes to this policy</h2>
          <p>
            We may update this policy from time to time. The &ldquo;Last updated&rdquo; date at the top
            will reflect any changes. Material changes will be communicated by email to registered users.
          </p>

          <h2>11. Contact</h2>
          <p>
            {COMPANY}<br />
            {COMPANY_LOCATION}<br />
            <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>
          </p>
        </div>
      </div>
    </div>
  );
}

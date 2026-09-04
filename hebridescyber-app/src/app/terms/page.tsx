import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Terms of Service — Hebrides Cyber",
  description: "The terms that apply when you use Hebrides Cyber's scanning, audit, and penetration-testing services.",
};

const LAST_UPDATED = "27 August 2026";
const CONTACT_EMAIL = "hello@hebridescyber.co.uk";
const COMPANY = "Hebrides Cyber";
const COMPANY_LOCATION = "Isle of Lewis, Scotland, UK";

export default function TermsPage() {
  return (
    <div className="bg-slatelight dark:bg-cyberbg min-h-screen">
      <div className="bg-grid pointer-events-none fixed inset-0 opacity-0 dark:opacity-20" />

      <div className="relative mx-auto max-w-3xl px-6 py-16">
        <Link
          href="/"
          className="mb-8 inline-block font-mono text-xs text-slatedark/50 hover:text-atlantic dark:text-cybertext/40 dark:hover:text-neon transition-colors"
        >
          ← Back to home
        </Link>

        <div className="mb-10">
          <p className="font-mono text-xs text-neon mb-2" aria-hidden="true">// terms-of-service.md</p>
          <h1 className="text-3xl font-bold text-slatedark dark:text-cybertext">Terms of Service</h1>
          <p className="mt-2 text-sm text-slatedark/50 dark:text-cybertext/40">Last updated: {LAST_UPDATED}</p>
        </div>

        <div className="prose prose-slate max-w-none dark:prose-invert dark:prose-headings:text-neon dark:prose-a:text-neon dark:prose-strong:text-cybertext dark:prose-code:text-neon dark:prose-code:bg-cyberpanel">
          <h2>1. Who we are and acceptance of these terms</h2>
          <p>
            {COMPANY} (&ldquo;we&rdquo;, &ldquo;us&rdquo;, &ldquo;our&rdquo;) is based in the {COMPANY_LOCATION}.
            By creating an account, purchasing a subscription, or engaging us for a one-off audit or
            penetration test, you (&ldquo;Customer&rdquo;, &ldquo;you&rdquo;) agree to these Terms. If you
            don&apos;t agree, please don&apos;t use the service.
          </p>

          <h2>2. The service</h2>
          <p>We provide:</p>
          <ul>
            <li>
              <strong>Automated Security Score subscriptions</strong> (Basic/Pro/Agency) — scheduled automated
              scanning, a scored report, and remediation guidance, per the plan tier described on{" "}
              <Link href="/pricing">/pricing</Link>.
            </li>
            <li>
              <strong>One-off audits</strong> (Small Website Audit / Standard Web App Audit / Full SaaS Audit) —
              a mix of automated scanning and, at the higher tiers, manual testing, delivered as a written report.
            </li>
            <li>
              <strong>Manual penetration-test engagements and other add-ons</strong>, priced per engagement.
            </li>
          </ul>
          <p>
            The service identifies <strong>indicators</strong> of security weakness. It is not a guarantee
            that a target system is secure, free of vulnerabilities, or compliant with any particular
            standard — see §7 (Disclaimers).
          </p>

          <h2>3. Accounts</h2>
          <p>
            You must provide accurate registration information and keep your credentials confidential.
            You&apos;re responsible for activity under your account. Notify us immediately at{" "}
            <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a> if you suspect unauthorised access.
          </p>

          <h2>4. Authorisation to scan</h2>
          <p>
            <strong>
              This is the most important clause in these Terms for a service that runs active security
              testing against infrastructure you specify.
            </strong>
          </p>
          <p>By submitting any URL, domain, or system for scanning — automated or manual — you represent and warrant that:</p>
          <ul>
            <li>you own the target, or</li>
            <li>
              you have explicit, current authorisation from the owner to conduct security testing against
              it, including active/intrusive testing (port scanning, vulnerability probing, SQL injection
              testing, cross-site-scripting testing, and the other techniques our extended scanning tier and
              manual engagements use).
            </li>
          </ul>
          <p>
            We verify domain ownership via a DNS or file-based check before running scheduled or on-demand
            automated scans (see our <Link href="/privacy">Privacy Policy</Link>), but this verification does
            not itself constitute legal authorisation to test, and manual/one-off engagements may rely on your
            representation alone.
          </p>
          <p>
            <strong>You agree to indemnify and hold us harmless</strong> from any claim, loss, or liability
            arising from your submission of a target you were not authorised to test. We reserve the right to
            suspend or terminate your account and refuse service if we reasonably believe a submitted target
            was not authorised.
          </p>

          <h2>5. Acceptable use</h2>
          <p>You will not:</p>
          <ul>
            <li>use the service to test a target you&apos;re not authorised to test (§4);</li>
            <li>use the service to develop or launch attacks against third parties outside the scope of a specific, authorised engagement;</li>
            <li>attempt to circumvent rate limits, plan restrictions, or access another customer&apos;s data;</li>
            <li>resell or provide the service to a third party outside a specifically contracted white-label/agency arrangement (Agency plan).</li>
          </ul>
          <p>We may suspend accounts that violate this section without refund.</p>

          <h2>6. Fees, billing, and cancellation</h2>
          <ul>
            <li>
              Monthly subscription plans are billed via Stripe on a recurring basis at the price shown on{" "}
              <Link href="/pricing">/pricing</Link> at signup. You can cancel at any time via the billing
              portal; cancellation takes effect at the end of the current billing period, with no partial
              refund for the remainder.
            </li>
            <li>One-off audits are invoiced 50% upfront, remainder on delivery, per <Link href="/pricing">/pricing</Link>.</li>
            <li>We may change prices for future billing periods with notice; changes don&apos;t apply retroactively to a period already paid for.</li>
          </ul>

          <h2>7. Disclaimers</h2>
          <p>
            The service is provided &ldquo;as is.&rdquo; Automated and manual security testing can never
            guarantee the discovery of every vulnerability, and a clean or high-scoring report is not a
            certification that a target is secure. We make no warranty, express or implied, of
            merchantability, fitness for a particular purpose, or that the service will be uninterrupted or
            error-free.
          </p>
          <p>
            Cyber Essentials / compliance-framework references in reports are automated indicators only,
            never a certification.
          </p>

          <h2>8. Limitation of liability</h2>
          <p>
            To the maximum extent permitted by law, our total liability to you arising out of or related to
            these Terms or the service is limited to the fees you paid us in the 12 months preceding the
            claim. We are not liable for indirect, incidental, special, consequential, or lost-profit
            damages. Nothing in these Terms excludes or limits liability for death or personal injury caused
            by negligence, fraud or fraudulent misrepresentation, or any other liability that cannot be
            excluded or limited under UK law.
          </p>

          <h2>9. Intellectual property</h2>
          <p>
            Scan reports and findings we generate for you are yours to use for your own security purposes.
            We retain ownership of our underlying tooling, scanner logic, and report templates. You grant us
            a licence to process the target/scan data you submit solely to provide the service.
          </p>

          <h2>10. Termination</h2>
          <p>
            Either party may terminate a subscription per §6. We may terminate or suspend access immediately
            for a breach of §4 or §5, or if required by law.
          </p>

          <h2>11. Data protection</h2>
          <p>
            Personal data is handled per our <Link href="/privacy">Privacy Policy</Link> — retention periods,
            data-subject rights, and our processor list live there, not duplicated here.
          </p>

          <h2>12. Governing law</h2>
          <p>These Terms are governed by the law of Scotland, and the Scottish courts have exclusive jurisdiction over any dispute arising from them.</p>

          <h2>13. Changes to these Terms</h2>
          <p>
            We may update these Terms from time to time. The &ldquo;Last updated&rdquo; date at the top will
            reflect any changes. Material changes will be communicated by email to registered users.
          </p>

          <h2>14. Contact</h2>
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

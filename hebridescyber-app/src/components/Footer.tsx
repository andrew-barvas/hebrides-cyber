import Link from "next/link";
import { CookieSettingsButton } from "./CookieConsent";
import { statusPageUrl } from "@/lib/statusPage";

// Layout follows the pattern security vendors' sites share (Intruder,
// Detectify, Pentest-Tools, Huntress, compared 2026-11-02): a brand block with
// a one-line description and a contact address, a few titled link columns,
// and a bottom bar with the copyright and the legal links. The sector landing
// pages (/tourism, /churches, /local-trades) are left out on purpose; the
// services page and the sitemap still reach them.

const productLinks = [
  { href: "/services", label: "Services" },
  { href: "/what-we-check", label: "What we check" },
  { href: "/pricing", label: "Pricing" },
  { href: "/sample-reports", label: "Sample reports" },
];

// The landing pages a visitor arriving from search or a campaign needs to
// find from anywhere, not only from a link they were sent.
const resourceLinks = [
  { href: "/web-check-alternative", label: "NCSC Web Check alternative" },
  { href: "/cyber-essentials", label: "Cyber Essentials readiness" },
  { href: "/ai-threats", label: "AI-driven threats" },
  { href: "/docs/ci", label: "CI/CD integration" },
  { href: "/blog", label: "Blog" },
];

const companyLinks = [
  { href: "/contact", label: "Contact" },
  { href: "/agencies", label: "For agencies" },
];

// E-23 (docs/ENHANCEMENTS.md): /privacy was previously reachable only from
// the dashboard (behind login) and the cookie-consent banner — a public
// privacy policy unreachable from the public site is a straightforward
// compliance defect. /terms is new alongside it (E-09/BETA-B1).
const legalLinks = [
  { href: "/trust", label: "Trust" },
  { href: "/privacy", label: "Privacy Policy" },
  { href: "/terms", label: "Terms of Service" },
];

const CONTACT_EMAIL = "hello@hebridescyber.co.uk";

const linkClass = "hover:text-neon transition-colors";

function LinkColumn({ title, links }: { title: string; links: { href: string; label: string }[] }) {
  return (
    <nav aria-label={title}>
      <h2 className="mb-3 font-mono text-xs uppercase tracking-wider text-cybertext">
        <span aria-hidden="true" className="text-neon">
          //{" "}
        </span>
        {title}
      </h2>
      <ul className="space-y-2">
        {links.map(({ href, label }) => (
          <li key={href}>
            <Link href={href} className={linkClass}>
              {label}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}

export default function Footer() {
  const status = statusPageUrl();
  return (
    <footer className="border-t border-cyberborder bg-cyberbg text-sm text-cybermuted">
      <div className="mx-auto grid max-w-6xl gap-8 px-4 py-10 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <Link href="/" className="font-mono text-base font-bold text-cybertext">
            <span aria-hidden="true" className="text-neon">
              &gt;{" "}
            </span>
            Hebrides_Cyber
          </Link>
          <p className="mt-3 max-w-xs">
            Website and email security checks for UK small businesses, with fixes in plain English.
          </p>
          <a href={`mailto:${CONTACT_EMAIL}`} className={`mt-3 inline-block ${linkClass}`}>
            {CONTACT_EMAIL}
          </a>
        </div>
        <LinkColumn title="Product" links={productLinks} />
        <LinkColumn title="Resources" links={resourceLinks} />
        <LinkColumn title="Company" links={companyLinks} />
      </div>
      <div className="border-t border-cyberborder">
        <div className="mx-auto flex max-w-6xl flex-col gap-3 px-4 py-5 sm:flex-row sm:items-center sm:justify-between">
          <p className="font-mono">
            <span aria-hidden="true" className="text-neon">$</span>{" "}
            &copy; {new Date().getFullYear()} Hebrides Cyber — Isle of Lewis
          </p>
          <nav aria-label="Legal" className="flex flex-wrap gap-x-5 gap-y-2">
            {legalLinks.map(({ href, label }) => (
              <Link key={href} href={href} className={linkClass}>
                {label}
              </Link>
            ))}
            {/* The privacy policy (section 2e) promises this control: withdrawing
                consent has to be as easy as giving it. */}
            <CookieSettingsButton className={linkClass} />
            {status && (
              <a href={status} target="_blank" rel="noopener noreferrer" className={linkClass}>
                Status
              </a>
            )}
          </nav>
        </div>
      </div>
    </footer>
  );
}

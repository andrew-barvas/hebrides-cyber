import Link from "next/link";

// The landing pages a visitor arriving from search or a campaign needs to
// find from anywhere, not only from a link they were sent.
const resourceLinks = [
  { href: "/web-check-alternative", label: "NCSC Web Check alternative" },
  { href: "/cyber-essentials", label: "Cyber Essentials readiness" },
  { href: "/ai-threats", label: "AI-driven threats" },
  { href: "/sample-reports", label: "Sample reports" },
  { href: "/agencies", label: "For agencies" },
  { href: "/docs/ci", label: "CI/CD integration" },
];

const industryLinks = [
  { href: "/tourism", label: "Tourism & Hospitality" },
  { href: "/churches", label: "Churches & Charities" },
  { href: "/local-trades", label: "Local Trades" },
];

// E-23 (docs/ENHANCEMENTS.md): /privacy was previously reachable only from
// the dashboard (behind login) and the cookie-consent banner — a public
// privacy policy unreachable from the public site is a straightforward
// compliance defect. /terms is new alongside it (E-09/BETA-B1).
const legalLinks = [
  { href: "/privacy", label: "Privacy Policy" },
  { href: "/terms", label: "Terms of Service" },
];

export default function Footer() {
  return (
    <footer className="border-t border-cyberborder bg-cyberbg py-8 text-center text-sm text-cybertext/60">
      <nav aria-label="Resources" className="mb-4 flex flex-wrap justify-center gap-x-5 gap-y-2 px-4">
        {resourceLinks.map(({ href, label }) => (
          <Link key={href} href={href} className="hover:text-neon transition-colors">
            {label}
          </Link>
        ))}
      </nav>
      <nav aria-label="Industries" className="mb-4 flex flex-wrap justify-center gap-x-5 gap-y-2 px-4">
        {industryLinks.map(({ href, label }) => (
          <Link key={href} href={href} className="hover:text-neon transition-colors">
            {label}
          </Link>
        ))}
      </nav>
      <nav aria-label="Legal" className="mb-4 flex flex-wrap justify-center gap-x-5 gap-y-2 px-4">
        {legalLinks.map(({ href, label }) => (
          <Link key={href} href={href} className="hover:text-neon transition-colors">
            {label}
          </Link>
        ))}
      </nav>
      <p className="font-mono">
        <span aria-hidden="true" className="text-neon">$</span>{" "}
        &copy; {new Date().getFullYear()} Hebrides Cyber — Isle of Lewis
      </p>
    </footer>
  );
}

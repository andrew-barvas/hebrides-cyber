// What to do about a lookalike domain (COMPETITOR-ANALYSIS-ENTERPRISE-2026-11.md
// idea 3). lookalikeDomainMonitor.ts tells an owner that a domain one
// character away from theirs has a certificate; this module tells them what
// to do next, the same way on the Assets page, in the Lookout report and in
// the alert email. Pure and client-safe.
//
// Defensive steps only: block it in the customer's own mail system, report it
// to the registrar and the NCSC, warn staff. Nothing here contacts the domain.
// A lookalike may be unrelated to the customer, so every step is phrased as
// "if", and the report template asks the registrar to investigate rather than
// asserting abuse.

export const LOOKALIKE_TECHNIQUE_LABELS: Readonly<Record<string, string>> = {
  omission: "a character removed",
  doubling: "a character doubled",
  transposition: "two characters swapped",
  hyphenation: "a hyphen inserted",
  substitution: "a character swapped for a lookalike",
  "tld-swap": "a different top-level domain",
};

/** Plain-English name for how a lookalike was made ("a character removed"). */
export function lookalikeTechniqueLabel(technique: string): string {
  return LOOKALIKE_TECHNIQUE_LABELS[technique] ?? technique;
}

export type LookalikeInput = {
  /** The lookalike, e.g. "examp1e.co.uk". */
  domain: string;
  /** The customer's own domain it resembles. */
  targetDomain: string;
  /** How it differs, in plain English ("a character removed"). */
  how: string;
  /** When our sweep first spotted it (ISO). */
  spottedAt?: string | null;
};

export type ResponseStep = { title: string; body: string; link?: { label: string; href: string } };

export type LookalikeResponse = {
  summary: string;
  steps: ResponseStep[];
  abuseReport: { subject: string; body: string };
};

/** ICANN Lookup finds the registrar and its abuse contact for gTLDs and the ccTLDs that publish RDAP (including .uk). */
export function registrarLookupUrl(domain: string): string {
  return `https://lookup.icann.org/en/lookup?name=${encodeURIComponent(domain)}`;
}

export const NCSC_EMAIL_REPORT_ADDRESS = "report@phishing.gov.uk";
export const NCSC_WEBSITE_REPORT_URL = "https://www.ncsc.gov.uk/section/about-this-website/report-scam-website";

function formatDate(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : new Date(t).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
}

/** Pure. The response kit for one lookalike. */
export function buildLookalikeResponse(input: LookalikeInput): LookalikeResponse {
  const { domain, targetDomain, how } = input;
  const spotted = formatDate(input.spottedAt);

  const steps: ResponseStep[] = [
    {
      title: "Don't visit it from a work device",
      body: `Treat ${domain} as hostile until you know otherwise. If anyone has already entered a password on it, change that password and turn on multi-factor sign-in.`,
    },
    {
      title: "Block it in your email",
      body:
        `Microsoft 365: in the Microsoft Defender portal open Email & collaboration → Policies & rules → Threat policies → Tenant Allow/Block Lists → Domains & addresses, and add ${domain} as a block. ` +
        `Google Workspace: in the Admin console open Apps → Google Workspace → Gmail → Spam, Phishing and Malware → Blocked senders, and add ${domain}. ` +
        `Either way, mail from it stops reaching your staff.`,
    },
    {
      title: "Warn your staff",
      body: `Tell everyone that ${domain} is not yours and to check the sender's address carefully, especially on invoices, payment changes and password requests. If customers could be targeted, remind them how you normally contact them.`,
    },
    {
      title: "Find the registrar and report it",
      body: `Look up who registered ${domain} and send their abuse contact the report below. Add any evidence you have, such as emails received or screenshots.`,
      link: { label: `Look up ${domain}`, href: registrarLookupUrl(domain) },
    },
    {
      title: "Report it to the NCSC",
      body: `If it sends phishing emails, forward them to ${NCSC_EMAIL_REPORT_ADDRESS}. If it hosts a fake site, report the address to the NCSC, which can have scam sites taken down.`,
      link: { label: "Report a scam website", href: NCSC_WEBSITE_REPORT_URL },
    },
    {
      title: "Consider registering the closest variants yourself",
      body: `Registering the most likely misspellings of ${targetDomain} costs a few pounds a year each and stops the next one being used against you.`,
    },
  ];

  const abuseReport = {
    subject: `Abuse report: ${domain} may be impersonating ${targetDomain}`,
    body: [
      "Hello,",
      "",
      `I'm writing about the domain ${domain}. It is one character different from our domain, ${targetDomain} (${how}), and has a TLS certificate issued for it${spotted ? ` (we first saw it on ${spotted})` : ""}.`,
      "",
      "We believe it may be used to impersonate us, for example to send phishing emails to our staff or customers. [Add any evidence here: emails received, with full headers, or screenshots of the site.]",
      "",
      "Please investigate it under your abuse policy and let us know the outcome.",
      "",
      "Thank you,",
      "[Your name]",
      `[Your role], ${targetDomain}`,
    ].join("\n"),
  };

  return {
    summary: `${domain} looks like ${targetDomain} (${how}). It may be unrelated to you, but a near-identical domain with a certificate is a common setup for phishing your staff or customers.`,
    steps,
    abuseReport,
  };
}

/** Pure. The three steps short enough for an alert email. */
export function emailResponseSteps(): string[] {
  return [
    "Block the domain in Microsoft 365 or Google Workspace so its mail never reaches your staff.",
    "Warn your staff, especially whoever handles invoices and payments.",
    "Report it to the registrar (we've written the report for you) and phishing emails to the NCSC at report@phishing.gov.uk.",
  ];
}

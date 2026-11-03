import type { Metadata } from "next";
import { mainSiteUrl } from "@/lib/productSites";
import { CtaLink, FaqList, FeatureCard, MockWindow, SectionHeading, SectionNav, Tick } from "@/components/product-site/ProductSite";

// Lookout: managed exposure review. Also served at lookout.hebridescyber.co.uk
// (src/lib/productSites.ts). Copy comes from marketing/17-lookout-managed-
// exposure-review.md; design and decisions from docs/DEFENSIVE-ASSESSMENT-PLAN.md.
//
// Claims rule (OT-14): every feature on this page maps to built code or the
// documented manual service on the day it is live. Deliberately left out until
// they are true: checkout (Stripe prices, OT-34), the included-estate limits
// (OT-42), the document-metadata check (not in the `exposure` profile), passive
// header checks via ZAP (PR #152) and "what to log" guidance. "What Lookout
// sends to your systems" must stay, and must change whenever the `exposure`
// profile or the base suite does. Name no tools.

export const metadata: Metadata = {
  title: "Lookout: managed exposure review for UK businesses — Hebrides Cyber",
  description:
    "Daily checks of what the internet can see of your business, and an engineer-written report on what to fix first. Not a penetration test. From £149 a month.",
  alternates: { canonical: mainSiteUrl("/lookout") },
};

const SECTIONS = [
  { href: "#what-you-get", label: "What you get" },
  { href: "#how-it-works", label: "How it works" },
  { href: "#what-we-send", label: "What we send" },
  { href: "#compare", label: "Compare" },
  { href: "#plans", label: "Plans" },
  { href: "#faq", label: "FAQ" },
];

const FEATURES = [
  {
    title: "A clear picture of what's exposed",
    body: "We map the websites, subdomains and internet-facing services connected to your verified domains, and tell you when something new appears.",
  },
  {
    title: "Known weaknesses and risky settings",
    body: "Out-of-date and unsupported software, weak encryption, missing security settings, exposed admin pages and files that should not be public.",
  },
  {
    title: "Email and domain protection",
    body: "Whether your domain can be used to send spoofed email, and whether your domain registration and certificates are about to lapse.",
  },
  {
    title: "Fixes in plain English",
    body: "Every finding says what it means for your business, how to fix it and roughly how long it takes, ranked by urgency.",
  },
  {
    title: "Evidence for insurers and customers",
    body: "Findings are mapped to Cyber Essentials, ISO 27001 and other standards, and to MITRE ATT&CK, so you can answer security questionnaires with something to show. Mapped to, never certified by.",
  },
  {
    title: "Known-exploited flags",
    body: "Software weaknesses are checked against CISA's catalogue of vulnerabilities attackers are actively using, and those go to the top of your list.",
  },
  {
    title: "A named engineer, not a ticket queue",
    body: "A review call each quarter (two on Assured) with the person who wrote your report.",
  },
  {
    title: "Confirmation that fixes worked",
    body: "Tell us when something is fixed and we confirm it from the next scheduled check.",
  },
];

const STEPS = [
  { n: "01", title: "Verify", body: "You list your domains and public IP addresses and prove you own them, with a DNS record or a file on your site. Nothing is checked before that." },
  { n: "02", title: "Agree the scope", body: "We confirm what is in and out, a time window for the checks, and who we contact about anything urgent." },
  { n: "03", title: "Daily checks", body: "Automated, non-intrusive checks run every day on the agreed estate, and keep a history so changes stand out." },
  { n: "04", title: "Engineer review", body: "An engineer removes false positives, groups duplicates and ranks what is left by how exposed it is and what it would mean for your business." },
  { n: "05", title: "Report and call", body: "A short report written for the person in charge of the business, then a call to talk it through." },
  { n: "06", title: "Fix and confirm", body: "You fix; we confirm from the next check and track it in the report until it's closed." },
];

const COMPARE_ROWS: { label: string; scanner: string; lookout: string; pentest: string }[] = [
  { label: "Who it's for", scanner: "You want to watch a website yourself", lookout: "You want someone to tell you what matters", pentest: "A contract, insurer or regulator asks for a test" },
  { label: "How often", scanner: "Daily or weekly, automatic", lookout: "Daily checks, monthly or quarterly report", pentest: "Once, at a point in time" },
  { label: "Who reads the results", scanner: "You, in the dashboard", lookout: "An engineer, then you on a call", pentest: "A tester, in a final report" },
  { label: "Tries to break in", scanner: "No", lookout: "No", pentest: "Yes, with written authorisation" },
  { label: "Price", scanner: "From £20 a month", lookout: "From £149 a month", pentest: "Quoted per engagement" },
];

const FAQ = [
  {
    q: "Is this a penetration test?",
    a: "No. A penetration test tries to break in. Lookout is a regular, defensive review of what is exposed and misconfigured, and it never tries to exploit anything. If you need a hands-on penetration test for a contract or regulator, ask us and we will point you to the right option.",
  },
  {
    q: "Will the checks slow down or break my website?",
    a: "They are designed to be light: ordinary page requests, a fixed list of file and port checks, and no test code sent to your forms. They only cover domains you have verified, inside a time window we agree with you.",
  },
  {
    q: "Will it show up in my logs?",
    a: "Yes. Our checks are real traffic, so your website logs, firewall or hosting provider may record them, and your login page will see five attempts with made-up details. We tell you when the first checks start.",
  },
  {
    q: "Do you watch my systems around the clock?",
    a: "No. Lookout is daily automated checking plus engineer review, not 24/7 monitoring or incident response. If we see something serious, we email your nominated contact, normally within one working day. That is a best-effort notice, not a guaranteed response time.",
  },
  {
    q: "What do I need to give you?",
    a: "Your domains and public IP addresses, a contact for urgent findings, and confirmation that you own them or are authorised to have them tested. You verify each domain with a DNS record or a file on your site before anything is checked.",
  },
  {
    q: "Does it make me Cyber Essentials certified?",
    a: "No. It helps you prepare and gives you evidence. Certification is done by an accredited certification body.",
  },
  {
    q: "How is this different from your scanner subscription?",
    a: (
      <>
        The <a href={mainSiteUrl("/pricing")} className="text-neon hover:underline">scanner</a> is self-serve: you run it and read the dashboard. Lookout uses the same checks across your whole estate, adds engineer review, a written report, calls and fix confirmation. Existing scanner customers can move up at any time.
      </>
    ),
  },
];

function ExposureMockup() {
  const rows = [
    { sev: "High", tone: "text-danger", item: "Remote desktop open to the internet", where: "203.0.113.24", ref: "T1133" },
    { sev: "High", tone: "text-danger", item: "Unsupported web server version", where: "shop.example.co.uk", ref: "T1190" },
    { sev: "Medium", tone: "text-warning", item: "Domain can be spoofed in email", where: "example.co.uk", ref: "T1566" },
    { sev: "Low", tone: "text-cybertext/70", item: "Certificate expires in 18 days", where: "mail.example.co.uk", ref: "—" },
  ];
  return (
    <MockWindow title="lookout · example.co.uk · this month">
      <div className="mb-4 grid grid-cols-3 gap-3 text-center">
        <div className="rounded-lg border border-cyberborder p-3">
          <div className="text-2xl font-bold text-neon">23</div>
          <div className="text-[11px] uppercase tracking-wider text-cybertext/60">Assets</div>
        </div>
        <div className="rounded-lg border border-cyberborder p-3">
          <div className="text-2xl font-bold">+2</div>
          <div className="text-[11px] uppercase tracking-wider text-cybertext/60">New this month</div>
        </div>
        <div className="rounded-lg border border-cyberborder p-3">
          <div className="text-2xl font-bold text-warning">4</div>
          <div className="text-[11px] uppercase tracking-wider text-cybertext/60">To fix</div>
        </div>
      </div>
      <p className="mb-2 font-mono text-[11px] uppercase tracking-wider text-cybertext/60">Fix first</p>
      <ul className="divide-y divide-cyberborder text-sm">
        {rows.map((r) => (
          <li key={r.item} className="flex items-start justify-between gap-3 py-2">
            <div className="min-w-0">
              <span className={`mr-2 font-mono text-[11px] font-semibold uppercase ${r.tone}`}>{r.sev}</span>
              <span className="text-cybertext/90">{r.item}</span>
              <div className="truncate font-mono text-[11px] text-cybertext/50">{r.where}</div>
            </div>
            <span className="shrink-0 font-mono text-[11px] text-cybertext/60">{r.ref}</span>
          </li>
        ))}
      </ul>
    </MockWindow>
  );
}

export default function LookoutPage() {
  return (
    <div className="bg-cyberbg text-cybertext">
      <section className="relative overflow-hidden border-b border-cyberborder">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative mx-auto grid max-w-6xl items-center gap-10 px-4 py-16 sm:px-6 lg:grid-cols-2 lg:py-24">
          <div>
            <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
              <span className="text-cybertext/60">$</span> lookout.watch()
            </p>
            <p className="mb-2 text-sm font-semibold uppercase tracking-wider text-cybertext/60">Lookout by Hebrides Cyber</p>
            <h1 className="text-4xl font-bold leading-tight sm:text-5xl">
              Know what the internet can see of your business, and what to fix first.
            </h1>
            <p className="mt-5 text-lg text-cybertext/70 leading-relaxed">
              A managed exposure review for UK businesses. We check your websites, domains and internet-facing services every day, and a named engineer tells you, in plain English, what matters and what to do about it.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <CtaLink href={mainSiteUrl("/contact")}>Book a call about Lookout</CtaLink>
              <CtaLink href={mainSiteUrl("/sample-reports")} variant="secondary">
                See what&apos;s in a report
              </CtaLink>
            </div>
            <p className="mt-4 max-w-xl text-xs text-cybertext/60 leading-relaxed">
              Not a penetration test. We test what is visible from the internet for known weaknesses and risky settings, and we never try to break in.
            </p>
          </div>
          <ExposureMockup />
        </div>
      </section>

      <SectionNav label="Lookout sections" items={SECTIONS} />

      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <section aria-labelledby="pitch-heading" className="py-16">
          <SectionHeading
            id="pitch-heading"
            overline="the problem"
            title="Most businesses have more online than they realise"
            intro="Old subdomains, forgotten test sites, open services and out-of-date software. Lookout finds them, checks them every day for known weaknesses and risky settings, and an engineer turns the results into a short report written for the person in charge of the business, not just the person who looks after the servers. You get a clear list of what to fix first, a call to talk it through, and confirmation once each fix has worked."
          />
        </section>

        <section id="what-you-get" aria-labelledby="features-heading" className="scroll-mt-16 pb-16">
          <SectionHeading id="features-heading" overline="what you get" title="Everything an outsider could find, explained" />
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {FEATURES.map((f) => (
              <FeatureCard key={f.title} title={f.title}>
                {f.body}
              </FeatureCard>
            ))}
          </div>
        </section>

        <section id="how-it-works" aria-labelledby="how-heading" className="scroll-mt-16 pb-16">
          <SectionHeading id="how-heading" overline="how it works" title="From verified domains to confirmed fixes" />
          <ol className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {STEPS.map((s) => (
              <li key={s.n} className="rounded-lg border border-cyberborder bg-cyberpanel p-5">
                <span className="font-mono text-sm text-neon">{s.n}</span>
                <h3 className="mt-1 font-semibold">{s.title}</h3>
                <p className="mt-2 text-sm text-cybertext/70 leading-relaxed">{s.body}</p>
              </li>
            ))}
          </ol>
        </section>

        <section id="what-we-send" aria-labelledby="send-heading" className="scroll-mt-16 pb-16">
          <SectionHeading
            id="send-heading"
            overline="no surprises"
            title="What Lookout sends to your systems"
            intro="Lookout is an active assessment, not passive observation. To find what an outsider could find, our checks connect to your systems from the internet, much as a visitor or an outsider's automated tools would."
          />
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-lg border border-cyberborder bg-cyberpanel p-5">
              <h3 className="mb-3 font-semibold">Our checks</h3>
              <ul className="space-y-2 text-sm text-cybertext/70">
                <Tick>load pages from your websites, follow links on them (up to 50 pages, respecting your robots.txt) and read the files those pages link to</Tick>
                <Tick>request a fixed list of well-known file locations, such as old backups and configuration files, to see whether any are public</Tick>
                <Tick>connect to common network ports on your addresses to see which services answer, and identify the software behind them</Tick>
                <Tick>check for known misconfigurations and exposed admin pages</Tick>
                <Tick>submit your login page five times with made-up details, to check that it slows down repeated attempts</Tick>
              </ul>
            </div>
            <div className="rounded-lg border border-cyberborder bg-cyberpanel p-5">
              <h3 className="mb-3 font-semibold">They never</h3>
              <ul className="space-y-2 text-sm text-cybertext/70">
                <Tick>try to exploit a weakness, inject test code or commands into your forms or URLs, or guess passwords</Tick>
                <Tick>try to log in with real or default credentials, or go beyond what is reachable from the internet</Tick>
                <Tick>check anything you have not proved you own or are authorised to have tested</Tick>
              </ul>
              <p className="mt-4 text-xs text-cybertext/60 leading-relaxed">
                We agree a time window for the checks with you, and you may see our requests in your logs or your hosting provider&apos;s alerts. Tell your IT supplier before you start.
              </p>
            </div>
          </div>
        </section>

        <section id="compare" aria-labelledby="compare-heading" className="scroll-mt-16 pb-16">
          <SectionHeading
            id="compare-heading"
            overline="choosing the right option"
            title="Scanner, Lookout or a penetration test?"
            intro="Three different jobs. Many businesses start with the scanner, move to Lookout when they want someone to own the answer, and book a penetration test only when a contract or insurer asks for one."
          />
          <div className="overflow-x-auto rounded-lg border border-cyberborder bg-cyberpanel">
            <table className="w-full min-w-[640px] text-left text-sm">
              <caption className="sr-only">Scanner, Lookout and penetration testing compared</caption>
              <thead>
                <tr className="border-b border-cyberborder font-mono text-[11px] uppercase tracking-wider text-cybertext/60">
                  <th scope="col" className="px-4 py-3 font-medium"><span className="sr-only">Question</span></th>
                  <th scope="col" className="px-4 py-3 font-medium">Scanner</th>
                  <th scope="col" className="px-4 py-3 font-medium text-neon">Lookout</th>
                  <th scope="col" className="px-4 py-3 font-medium">Penetration test</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyberborder">
                {COMPARE_ROWS.map((r) => (
                  <tr key={r.label}>
                    <th scope="row" className="px-4 py-3 align-top font-medium text-cybertext/90">{r.label}</th>
                    <td className="px-4 py-3 align-top text-cybertext/70">{r.scanner}</td>
                    <td className="px-4 py-3 align-top text-cybertext/90">{r.lookout}</td>
                    <td className="px-4 py-3 align-top text-cybertext/70">{r.pentest}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section id="plans" aria-labelledby="plans-heading" className="scroll-mt-16 pb-16">
          <SectionHeading
            id="plans-heading"
            overline="clear, fixed pricing"
            title="Two plans, published prices"
            intro="Each plan includes a fixed amount of engineer time; larger estates are quoted separately. Every plan starts with a call to agree your scope."
          />
          <div className="grid gap-4 md:grid-cols-2">
            {[
              {
                name: "Essentials",
                price: "£149",
                alt: "£399 a quarter or £1,490 a year",
                items: ["Daily automated checks", "Engineer-written report every quarter", "30-minute review call each quarter", "Fix confirmation at the next report"],
              },
              {
                name: "Assured",
                price: "£299",
                alt: "£799 a quarter or £2,990 a year",
                items: [
                  "Daily automated checks",
                  "Engineer-written report every month",
                  "Two review calls each quarter",
                  "Fix confirmation within the month",
                  "Help with Cyber Essentials and insurance questionnaires",
                ],
              },
            ].map((plan) => (
              <div key={plan.name} className="flex flex-col rounded-xl border border-cyberborder bg-cyberpanel p-6">
                <h3 className="text-lg font-semibold">{plan.name}</h3>
                <p className="mt-2">
                  <span className="text-3xl font-bold">{plan.price}</span>
                  <span className="text-cybertext/60"> / month</span>
                </p>
                <p className="text-xs text-cybertext/60">or {plan.alt}</p>
                <ul className="mt-4 flex-1 space-y-2 text-sm text-cybertext/70">
                  {plan.items.map((i) => (
                    <Tick key={i}>{i}</Tick>
                  ))}
                </ul>
                <div className="mt-6">
                  <CtaLink href={mainSiteUrl("/contact")}>Book a call</CtaLink>
                </div>
              </div>
            ))}
          </div>
          <p className="mt-4 text-xs text-cybertext/60">
            Optional extras, quoted: Cyber Essentials readiness pack, insurance evidence pack, extra domains or IP addresses, board summary, CI/CD hardening workshop (£300). Not a penetration test.
          </p>
        </section>

        <section aria-labelledby="why-heading" className="pb-16">
          <SectionHeading id="why-heading" overline="why us" title="Why choose Hebrides Cyber" />
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <FeatureCard title="Local and accountable">You get a named engineer from the Isle of Lewis, not a ticket queue. We answer to the businesses we live and work alongside.</FeatureCard>
            <FeatureCard title="Engineers who explain">We are software engineers. We write reports for the owner first and the IT person second, so you can act on them the same day.</FeatureCard>
            <FeatureCard title="Thorough, never exploitative">We test what is visible from the internet and tell you exactly what our checks send. We never try to break in, and we only check domains you have verified.</FeatureCard>
            <FeatureCard title="Clear, fixed pricing">One monthly, quarterly or annual price per plan, published on this page. No surprise call-out fees for anything included.</FeatureCard>
          </div>
        </section>

        <section aria-labelledby="platform-heading" className="pb-16">
          <SectionHeading
            id="platform-heading"
            overline="built on the platform"
            title="The same checks our scanner customers rely on"
            intro="Lookout runs on the Hebrides Cyber platform, so you can see exactly what is checked and how we handle your data."
          />
          <ul className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
            {[
              { href: "/what-we-check", label: "What we check", note: "Every automated check, in plain terms" },
              { href: "/sample-reports", label: "Sample reports", note: "What a finished report looks like" },
              { href: "/trust", label: "Trust", note: "How we secure the platform and your data" },
              { href: "/login", label: "Customer sign-in", note: "Your findings and reports" },
            ].map((l) => (
              <li key={l.href}>
                <a href={mainSiteUrl(l.href)} className="block rounded-lg border border-cyberborder bg-cyberpanel p-4 hover:border-neon transition-colors">
                  <span className="font-semibold text-neon">{l.label} →</span>
                  <span className="mt-1 block text-cybertext/60">{l.note}</span>
                </a>
              </li>
            ))}
          </ul>
        </section>

        <section id="faq" aria-labelledby="faq-heading" className="scroll-mt-16 pb-16">
          <SectionHeading id="faq-heading" overline="questions" title="Frequently asked" />
          <FaqList items={FAQ} />
        </section>

        <section aria-labelledby="cta-heading" className="pb-20">
          <div className="rounded-xl border border-neon/30 bg-cyberpanel p-8 text-center">
            <h2 id="cta-heading" className="text-2xl font-bold">
              Find out what the internet can see of your business
            </h2>
            <p className="mx-auto mt-3 max-w-xl text-cybertext/70">
              A short call to understand your estate, then we&apos;ll tell you which plan fits. Prefer to try the checks yourself first? Run one free scan.
            </p>
            <div className="mt-6 flex flex-wrap justify-center gap-3">
              <CtaLink href={mainSiteUrl("/contact")}>Book a call about Lookout</CtaLink>
              <CtaLink href={mainSiteUrl("/signup")} variant="secondary">
                Run a free scan
              </CtaLink>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

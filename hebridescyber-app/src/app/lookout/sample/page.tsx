import type { Metadata } from "next";
import { mainSiteUrl } from "@/lib/productSites";
import { CtaLink } from "@/components/product-site/ProductSite";

// A sample Lookout report (COMPETITOR-ANALYSIS-ENTERPRISE-2026-11.md idea 11):
// what a customer actually receives, so a prospect can see the "named
// engineer" value before a call. The "See what's in a report" button on
// /lookout used to lead to the Scanner's sample reports instead.
//
// Rules (OT-14, marketing/19-advertising-plan.md §1):
//   - A fictional business on reserved .example domains, labelled as an
//     example throughout. Never a real customer.
//   - Only sections the real report has (lookoutReportPdf.ts and
//     /dashboard/lookout/<id>): the engineer's summary, the score over the
//     period, what to fix in order with notes, lookalike domains with what to
//     do, and acknowledgement. Breached accounts are left out until OT-17
//     switches them on.
//   - No tool names, no attack techniques.

export const metadata: Metadata = {
  title: "Sample Lookout report — Hebrides Cyber",
  description: "An example of the quarterly report a Lookout customer receives: an engineer's summary, the score over the period, and what to fix first, in plain English. Fictional business.",
  alternates: { canonical: mainSiteUrl("/lookout/sample") },
};

const SITES = [
  { host: "www.harbourbakery.example", start: 58, end: 81 },
  { host: "shop.harbourbakery.example", start: 64, end: 72 },
  { host: "staff.harbourbakery.example", start: 61, end: 49 },
];

// The weekly average of the three sites: starts at (58 + 64 + 61) / 3 and ends
// at (81 + 72 + 49) / 3, dipping in the last week when the rota site's problem
// appeared.
const WEEKLY = [61, 61, 62, 64, 64, 67, 71, 71, 73, 74, 76, 76, 67];

const ITEMS = [
  {
    severity: "high",
    title: "The staff rota site still runs software that stopped getting security fixes",
    host: "staff.harbourbakery.example",
    why: "Weaknesses found in it from now on will never be fixed, and this kind of software is a common way in for automated attacks.",
    note: "This is the old rota system your previous supplier set up. If nobody uses it, switching it off is the quickest fix; if it is still needed, ask them to move it to the current version.",
    owner: "Your IT supplier",
  },
  {
    severity: "medium",
    title: "Your domain doesn't yet tell receiving mail servers to reject fake emails",
    host: "harbourbakery.example",
    why: "Anyone can send email that appears to come from you, for example a fake invoice to a wholesale customer.",
    note: "Your email authentication is set up correctly now, so the remaining step is changing your DMARC policy from monitor-only to quarantine. Your reports for the last month show only your own systems sending, so it's safe to do.",
    owner: "You",
  },
  {
    severity: "medium",
    title: "The shop's checkout page allows an outdated encryption setting",
    host: "shop.harbourbakery.example",
    why: "Older browsers could be pushed onto weaker encryption. It's a setting at your shop provider, not a code change.",
    note: "In your shop platform's settings, turn on 'modern TLS only'. Takes five minutes.",
    owner: "You",
  },
];

const SEV: Record<string, string> = {
  high: "border-orange-400/40 bg-orange-400/10 text-orange-400",
  medium: "border-yellow-400/40 bg-yellow-400/10 text-yellow-400",
};

function change(start: number, end: number): string {
  const d = end - start;
  return d === 0 ? "no change" : d > 0 ? `+${d}` : `−${Math.abs(d)}`;
}

function Trend() {
  const w = 520;
  const h = 110;
  const x = (i: number) => 34 + (i / (WEEKLY.length - 1)) * (w - 44);
  const y = (s: number) => 12 + (h - 24) - (s / 100) * (h - 24);
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="h-auto w-full max-w-xl" role="img" aria-label="Example: average security score rising from 61 to 76 over the quarter, then dipping to 67">
      {[50, 75, 90].map((g) => (
        <g key={g}>
          <line x1={34} x2={w - 10} y1={y(g)} y2={y(g)} className="stroke-cyberborder" strokeWidth={1} />
          <text x={28} y={y(g) + 3} fontSize={9} textAnchor="end" className="fill-cybermuted">
            {g}
          </text>
        </g>
      ))}
      <polyline points={WEEKLY.map((s, i) => `${x(i)},${y(s)}`).join(" ")} fill="none" className="stroke-neon" strokeWidth={2} />
    </svg>
  );
}

export default function SampleLookoutReportPage() {
  return (
    <div className="min-h-screen bg-cyberbg text-cybertext">
      <main className="mx-auto max-w-3xl space-y-8 px-4 py-10 sm:px-6">
        <div className="rounded-lg border border-warning/40 bg-warning/10 px-4 py-2 text-sm text-warning" role="note">
          Example report. Harbour Bakery is a fictional business and every detail below is made up to show what a Lookout report contains.
        </div>

        <header className="border-b border-cyberborder pb-4">
          <p className="text-sm font-semibold uppercase tracking-wider text-cybertext/60">Lookout report · example</p>
          <h1 className="mt-1 text-3xl font-bold">Harbour Bakery: 1 July to 30 September</h1>
          <p className="mt-1 text-sm text-cybermuted">Prepared by your Hebrides Cyber engineer · also available as a dated PDF</p>
        </header>

        <section aria-labelledby="summary" className="space-y-3">
          <h2 id="summary" className="text-lg font-semibold">Summary</h2>
          <p className="text-cybertext/90">
            A good quarter. Your main website went from 58 to 81 after the hosting move in August, and the email changes we suggested in July are in place. One new problem appeared in the last week: the old staff rota site, which we think nobody uses, is running software that no longer gets security fixes. That&apos;s the one thing to deal with first.
          </p>
          <p className="text-cybertext/90">
            We also spotted a newly registered domain one letter different from yours. It may be unrelated, but it&apos;s worth blocking in your email now; the steps are below.
          </p>
        </section>

        <section aria-labelledby="trend" className="space-y-3 rounded-xl border border-cyberborder bg-cyberpanel p-5">
          <h2 id="trend" className="text-lg font-semibold">Your security score over this period</h2>
          <Trend />
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase text-cybermuted">
                <th className="py-1 pr-2 font-normal">Site</th>
                <th className="py-1 pr-2 font-normal">Start</th>
                <th className="py-1 pr-2 font-normal">End</th>
                <th className="py-1 font-normal">Change</th>
              </tr>
            </thead>
            <tbody>
              {SITES.map((s) => (
                <tr key={s.host} className="border-t border-cyberborder">
                  <td className="break-all py-1 pr-2">{s.host}</td>
                  <td className="py-1 pr-2 text-cybertext/80">{s.start}</td>
                  <td className="py-1 pr-2 font-semibold">{s.end}</td>
                  <td className="py-1 text-cybertext/80">{change(s.start, s.end)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <section aria-labelledby="fix" className="space-y-3">
          <h2 id="fix" className="text-lg font-semibold">What to fix, in order</h2>
          <ol className="space-y-4">
            {ITEMS.map((it, n) => (
              <li key={it.title} className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
                <p className="font-semibold">
                  <span className={`mr-2 rounded-sm border px-1.5 py-0.5 font-mono text-[11px] uppercase ${SEV[it.severity]}`}>{it.severity}</span>
                  {n + 1}. {it.title}
                </p>
                <p className="mt-1 break-all text-xs text-cybermuted">
                  {it.host} · Who fixes it: {it.owner}
                </p>
                <p className="mt-2 text-sm text-cybertext/80">
                  <strong>Why it matters:</strong> {it.why}
                </p>
                <p className="mt-2 text-sm text-cybertext/90">
                  <strong>Engineer&apos;s note:</strong> {it.note}
                </p>
              </li>
            ))}
          </ol>
        </section>

        <section aria-labelledby="lookalikes" className="space-y-3 rounded-xl border border-cyberborder bg-cyberpanel p-5">
          <h2 id="lookalikes" className="text-lg font-semibold">Lookalike domains</h2>
          <p className="text-sm text-cybertext/80">
            <span className="font-mono text-cybertext">harb0urbakery.example</span> looks like harbourbakery.example (a character swapped for a lookalike), spotted 22 September.
          </p>
          <p className="text-sm font-semibold">What to do</p>
          <ol className="list-decimal space-y-1 pl-5 text-sm text-cybertext/80">
            <li>Block the domain in Microsoft 365 or Google Workspace so its mail never reaches your staff.</li>
            <li>Warn your staff, especially whoever handles invoices and payments.</li>
            <li>Report it to the registrar, and forward any phishing emails from it to the NCSC.</li>
          </ol>
        </section>

        <section className="rounded-xl border border-cyberborder bg-cyberpanel p-5 text-sm text-cybertext/80">
          In your portal you&apos;d press <strong>&ldquo;I&apos;ve read this report&rdquo;</strong> to let your engineer know. It records that you&apos;ve read it; it isn&apos;t acceptance of any risk.
        </section>

        <div className="flex flex-wrap gap-3 border-t border-cyberborder pt-6">
          <CtaLink href={mainSiteUrl("/contact")}>Book a call about Lookout</CtaLink>
          <CtaLink href={mainSiteUrl("/lookout")} variant="secondary">
            Back to Lookout
          </CtaLink>
        </div>
        <p className="text-xs text-cybermuted">
          Prepared from automated external checks of what is reachable from the internet. An indicator, not a certification or a penetration test.
        </p>
      </main>
    </div>
  );
}

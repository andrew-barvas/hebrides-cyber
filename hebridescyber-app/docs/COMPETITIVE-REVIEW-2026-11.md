# Competitive review: Scanner, Lookout and Exploit (November 2026)

**As of 2026-11-02.** A fresh look at where the three-product set (Scanner,
Lookout, Exploit) stands against the market, where it is weak, and what would
move it ahead rather than level. It extends `COMPETITOR-MATRIX.md` (what each
side ships) and follows the rule in `COMPETITIVE-ANALYSIS.md` §1: **no
competitor price or limitation without a source and a date.**

## How far to trust this

Every competitor fact below comes from a web search on 2026-11-02. Almost all
of it is *third-party reported*: review sites, price aggregators and rival
vendors' comparison blogs, which often disagree with each other. Nothing here
was checked against the vendor's own pricing page. So:

- **Treat prices as ranges to be re-verified, not as quotable.** Do not paste
  any of them into marketing, a sales deck or the pricing page.
- A competitor "weakness" is stated only where a source says it, and is marked
  *reviewer-reported*. Nothing here is our own finding about a competitor.
- Our own facts are checked against the repo and carry a path.

Sources are listed at the end and cited by number, for example [S3].

## The three products and who they really compete with

| Our product | Status | Buyer | Competes with (by what the buyer is replacing) |
|---|---|---|---|
| **Scanner** | Live. Basic £20, Pro £35, Agency £75 a month; Tier A by quote and not marketed | UK SMEs, agencies, MSPs | Self-serve scanners and attack-surface tools; the retired NCSC Web Check |
| **Lookout** | Designed, not launched. Proposed £149 a month, with kill criteria in `DEFENSIVE-ASSESSMENT-PLAN.md` | An owner who wants "what matters, in plain English" | Managed attack-surface services; compliance platforms with scanning; doing nothing |
| **Exploit** | Plan only. Blocked on OT-13 (insurance and solicitor review) | A buyer who needs a real penetration test for a framework, insurer or customer | CREST-style manual tests; pentest-as-a-service; autonomous pentest products |

## What the market looks like

### Scanner: self-serve scanning and attack-surface monitoring

| Vendor | What is reported | Confidence |
|---|---|---|
| Intruder | Attack-surface monitoring plus infrastructure scanning. Pricing partly public and inconsistent between sources: a Cloud plan reported at $299 a month [S1], a paid tier from $499 a month on a Gartner listing [S1], a free plan, and an AI pentest add-on from $3,500 a test [S1]. Engines reported variously as OpenVAS with proprietary checks, or Nessus with nuclei [S1] | Low: aggregators disagree |
| Detectify | Application Scanning and Surface Monitoring sold separately. Most sources say about €90 a month for one domain and about €302 a month for 25 subdomains, one says a different yearly structure from €2,500 [S2]. Reviewer-reported: cost has risen, and authenticated and API/GraphQL coverage is thinner than some rivals [S2] | Low |
| Pentest-Tools.com | Official page reports NetSec from $95, WebNetSec from $140 and Pentest Suite from $190 a month, for 5 assets [S6]. Network scanner described as OpenVAS-based, 15,000+ CVEs [S6] | Medium: from the vendor's own page via search |
| Astra | Continuous DAST scanner at $69 to $199 a month, with authenticated scans included, and human pentests from about $3,000 to $6,000 a year, per aggregators [S5]. Says each manual pentest feeds its scanner [S5] | Low |
| CyberSmart | Sells Cyber Essentials and Cyber Essentials Plus certification (CE+ listed at £999 a year plus VAT on its plans page) and an "Active Protect" tier doing endpoint monitoring and vulnerability scanning, said to scan every 15 minutes [S7] | Medium: from its plans page |

### Lookout: managed exposure review

| Vendor | What is reported | Confidence |
|---|---|---|
| Hadrian | Managed external attack surface offering with continuous tuning, reporting and follow-up [S8]. An AWS Marketplace listing shows $50,000 for up to 250 assets [S8]. Says it serves small and medium enterprises among others [S8]. No source describes a named analyst or a periodic report for small buyers | Low-medium |
| Redcentric (G-Cloud) | Managed vulnerability scanning supporting Cyber Essentials Plus, standard price covering up to 750 hosts; price not shown [S7] | Low |
| Compliance and CE platforms | Bundle certification with device scanning (CyberSmart above) | Medium |

I found **no** source for a UK managed exposure review aimed at small
businesses that combines daily external checks, a plain-English report from a
named engineer and confirmation of fixes. That is an absence of evidence in a
few searches, not proof that no one sells it.

### Exploit: penetration testing

| Route | What is reported | Confidence |
|---|---|---|
| UK CREST-style manual test | Small web app tests commonly quoted about £2,000 to £6,000; commercial apps £6,000 to £18,000; tester day rates about £1,000 to £1,500; retest often extra. Several sources say CREST accreditation helps with supplier onboarding [S9] | Low: vendor blogs, mixed currencies |
| Pentest as a service (Cobalt) | Credit-based, mostly quote-only; tiers differ by start time and credit rollover; unlimited retests in term, per guides [S3] | Low |
| Autonomous web/app pentest (XBOW) | Attacks web apps and APIs and proves findings with a working exploit [S4]. Pricing now quote-based; earlier list prices of $4,000 to $8,000 a test reported, sources conflict [S4] | Low |
| Autonomous network pentest (Horizon3 NodeZero, Pentera) | NodeZero positioned network-first and production-safe; no public prices, one aggregator cites a median near $18,600 a year [S10]. Pentera described as the closest rival [S10] | Low |
| Intruder AI pentest add-on | From $3,500 a test, per a guide [S1] | Low |

One pattern worth acting on, still on low-confidence data: **most pentest and
managed-exposure offerings are quote-only or enterprise-priced** [S3, S4, S8,
S10]. A published, fixed price for a small buyer would be unusual.

## Where we are lacking

Ordered by how much it could cost us in a sale. The first three are the ones I
would not ignore.

1. **We cannot back a "pentest" with an accreditation.** Several UK sources tie
   CREST to supplier onboarding [S9]. Exploit has none and cannot be sold on
   price alone to a buyer whose procurement asks. (Owner decision, below.)
2. **We scan from the outside only.** Cyber Essentials Plus is a device-level
   check, and the competitor that sells CE+ also sells device scanning [S7]. An
   SME whose real need is "get certified" will choose the tool that covers
   devices. `COMPETITOR-MATRIX.md` gap 7 (customer-run agent) is the same hole
   seen from the enterprise side.
3. **Lookout and Exploit are not built.** Both rank below the market today on
   the only axis that matters: they cannot be bought. Lookout needs the
   exposure profile (merged, migration 065), the report, a named engineer and a
   first three pilot customers; Exploit needs OT-13.
4. **No platform certification.** No SOC 2, ISO 27001 or Cyber Essentials for
   ourselves (`/trust`, `docs/CONTROLS-EVIDENCE.md`). Security buyers ask.
5. **Throughput is untested under load.** Queue-based Actions workers; recent
   runs about 6 minutes, never measured at fleet scale
   (`COMPETITOR-MATRIX.md`, scale model).
6. **Depth gaps that competitors position**: reachability on dependency
   findings, a local command line, an analyst-review action on a finding
   (`COMPETITOR-MATRIX.md` gaps 4 to 6).

Where we are **not** behind, checked in the code: proof-of-exploit marking
(`src/lib/scanners/proofOfExploit.ts`), attack-path chokepoints
(`src/lib/attackPathAnalysis.ts`), SARIF/SBOM/VEX/CSV export, a CI gate that
fails only on new untriaged findings, customer-defined checks (#155, draft),
a no-signup check (#154, draft), TOTP in authenticated scans (#156), a
Prowler IAM wrapper (#158, awaiting a real-account run).

## How to overtake rather than catch up

The competitors above sell **separate products at separate prices**: a scanner,
or a managed service, or a pentest. Nobody in the sources sells the ladder
with one body of evidence running through it. That is the opening, and it is
already half-built.

### Bet 1: one finding, three levels of assurance (the ladder)

A Scanner finding that is "confirmed exploitable" (already marked in code) can
be promoted into a Lookout report line and, when a buyer needs a formal test,
into the Exploit scope with the evidence attached. Retest is the same check,
so a fix closes the same finding at every level. A buyer moving from a
£35 scan to a £149 review to a one-off test never starts over and never pays
for discovery twice. Competitors selling these as separate contracts cannot
match that without rebuilding their data model.
*Build:* a "request validation" action on a finding that creates a scoped
engagement draft (reuses `offensive_scan_authorizations` and the finding id).
About 1 week. No new offensive capability.

### Bet 2: publish the numbers

The repo already runs a scanner accuracy benchmark in CI. Competitor accuracy
claims in the sources are vendor-adjacent (for example a "zero false
positives" figure for XBOW from a vendor-adjacent blog [S4]). A public,
reproducible accuracy page, with the fixtures and the method, is something a
quote-only competitor will not copy. *Build:* a `/benchmark` page generated
from the CI result with caveats stated. 2 to 3 days.

### Bet 3: a fixed, published price for the small buyer

Most higher tiers are quote-only [S3, S4, S8, S10]. Lookout at a published
monthly price, and Exploit at published fixed-scope packages (once OT-13
clears), is a positioning wedge by itself. Needs the owner to confirm the
kill criteria and package scopes. No code.

### Bet 4: close the Cyber Essentials Plus gap honestly

Do not build an endpoint agent first. Ship a **CE+ readiness pack**: map every
external finding to the CE controls (already done in
`src/lib/scanners/compliance.ts`), add a device-check guide and an evidence
checklist, and partner with a certification body for the device test. Offer the
agent only if buyers ask (`COMPETITOR-MATRIX.md` gap 7). 1 week for the pack.

### Bet 5: be the transparent one

`marketing/17-lookout-managed-exposure-review.md` already commits to listing
exactly what Lookout sends to a customer's systems. Extend that to a public
"what every plan sends" page generated from `scanProfiles.ts`, so it cannot
drift. Black-box competitors cannot easily match it, and it answers the
authorisation question that every UK buyer's IT supplier asks. 2 days.

### Bet 6: the NCSC gap

Web Check and Mail Check ended on 31 March 2026, with Early Warning and DNS
Check continuing [S11]. The no-signup check (#154) and DMARC report ingestion
cover the same ground; add a UK-specific landing page and email-authentication
monitoring with alerts. Mostly marketing and a small page. Depends on #154
going live (needs Upstash, OT-06).

## What I would not do

- Build an autonomous multi-agent pentester to chase XBOW and NodeZero. Those
  are funded, specialised products [S4, S10]; Exploit's value is a scoped,
  contracted, analyst-reviewed test for a small buyer, and the evidence ladder
  above is where we are different.
- Match enterprise breadth (agents everywhere, on-premises packaging) before a
  buyer asks.
- Quote any competitor price from this file.

## Decisions only the owner can make

1. **CREST.** Pursue accreditation, or partner with an accredited tester to
   countersign Exploit reports? The partner route is faster and cheaper; it
   changes the margin and the report wording.
2. **OT-13** (insurance, solicitor-reviewed contract) before any Exploit
   traffic. Nothing in Exploit should be built beyond scoping until this clears.
3. **Lookout go or no-go** on the existing kill criteria: three hand-sold
   pilots, at least two of five prospects willing to pay £149 a month, a
   quarterly report in four analyst hours or fewer.
4. **Repository visibility** (public or private) before publishing benchmark
   fixtures and the "what we send" page.

## Suggested order

1. Land #151, #154, #155 and the owner items they depend on (OT-06 for #154).
2. Lookout pilots by hand (decision 3) while building Bet 1's action and Bet 5.
3. Bet 2 (benchmark page) and Bet 6 (NCSC landing) alongside, both small.
4. Bet 4 (CE+ pack) once a pilot customer asks for certification help.
5. Exploit scoping only after OT-13 and decision 1.

## Refreshing this file

Re-verify any cell against the vendor's own page before it is used outside
this repo, and record the page and date. Cells here that were not verified are
marked Low.

## Sources

All retrieved by web search on 2026-11-02; none opened on the vendor's own site
unless noted.

- **S1** Intruder pricing and features: [Beagle Security guide](https://beaglesecurity.com/blog/article/intruder-pricing.html), [Gartner listing](https://www.gartner.com/reviews/market/external-attack-surface-management/vendor/intruder/product/intruder-platform), [ethicalhacking.ai](https://ethicalhacking.ai/pricing/intruder-pricing)
- **S2** Detectify pricing and reviews: [Beagle Security](https://beaglesecurity.com/blog/article/detectify-pricing.html), [Capterra UK](https://www.capterra.co.uk/software/187632/detectify)
- **S3** Cobalt: [cobalt.io pricing](https://www.cobalt.io/platform/pricing), [Beagle Security](https://beaglesecurity.com/blog/article/cobalt-pricing.html)
- **S4** XBOW: [codeant.ai](https://codeant.ai/blogs/xbow-pricing), [ethicalhacking.ai](https://ethicalhacking.ai/pricing/xbow-pricing), [stackpick](https://stackpick.net/pricing/xbow/)
- **S5** Astra: [getastra.com pricing](https://www.getastra.com/lp/pentesting-pricing), [CostBench](https://costbench.com/software/bug-bounty-pentest/astra-security/)
- **S6** Pentest-Tools.com: [pricing](https://pentest-tools.com/pricing), [plan overview](https://pentest-tools.com/docs/account-billing/plans-and-limits/plan-overview)
- **S7** CyberSmart and G-Cloud: [CyberSmart plans](https://cybersmart.co.uk/plans), [G-Cloud listing](https://www.applytosupply.digitalmarketplace.service.gov.uk/g-cloud/services/440263161383872)
- **S8** Hadrian: [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-lwvqpwdtxzhke), [hadrian.io](https://hadrian.io/landing-page/attack-surface-management)
- **S9** UK penetration test costs: [Cyphere](https://thecyphere.com/blog/penetration-testing-cost/), [JUMPSEC](https://www.jumpsec.com/guides/how-much-does-penetration-testing-cost-in-the-uk/), [Blaze Infosec](https://www.blazeinfosec.com/?p=3764)
- **S10** Autonomous pentest comparisons: [ethicalhacking.ai](https://ethicalhacking.ai/compare/pentera-vs-horizon3), [Horizon3 pricing page via search](https://ethicalhacking.ai/pricing/horizon3-nodezero-pricing)
- **S11** NCSC retirement: [Redsift guide](https://redsift.com/guides/ncsc-mail-check-and-web-check-changes-migration-guide), [Report URI](https://blog.report-uri.com/when-free-national-security-tooling-goes-away-why-the-retirement-of-web-check-and-mail-check-matters/)

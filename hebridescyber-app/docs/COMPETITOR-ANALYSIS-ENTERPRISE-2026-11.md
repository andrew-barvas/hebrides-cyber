# Competitor analysis: Hebrides Cyber against global enterprise vendors (November 2026)

**As of 2026-11-20.** This file compares Scanner, Lookout, Exploit and the
planned phishing-awareness product with the large global vendors that sell
the same kind of thing to big companies. It then turns the comparison into a
ranked list of ideas.

It builds on the earlier work and doesn't repeat it:

- `COMPETITIVE-ANALYSIS.md`: rubric, anti-features, segments not to chase.
- `COMPETITOR-MATRIX.md`: SME scanners (Intruder, Probely, Detectify and others), dimension by dimension.
- `COMPETITIVE-REVIEW-2026-11.md`: UK pentest prices, Hadrian, the "ladder" and the six bets.
- `IMPROVEMENT-REVIEW-2026-11.md`: Aikido, Intruder, Vanta, UpGuard lessons, most of which are now built.

What's new here is the **enterprise** frame: EASM, vulnerability management,
security ratings, PTaaS and awareness platforms.

## How far to trust this

- **Our facts are checked against the code on `master` (3f74130)** and carry a
  path. Features that are built but switched off until an owner step say so.
- **Competitor facts come from web searches on 2026-11-20.** Most are
  third-party: price aggregators, review sites, and rival vendors' comparison
  blogs, which often disagree. Where a vendor's own page was the source, the
  confidence says so. Sources are numbered [E1] onwards at the end.
- In the matrices, **"n/f" means "not found in these searches"**. It is not a
  claim that the vendor lacks the feature.
- **Never paste a competitor price from this file into marketing, the pricing
  page or a sales deck** (`COMPETITIVE-ANALYSIS.md` §1, OT-14). Re-verify on
  the vendor's own page first.
- This is an internal planning document. Marketing-facing text has its own
  rules (`marketing/19-advertising-plan.md` §1): no tool names, no attack
  techniques, no Exploit until OT-13 and OT-51.

## 1. What we sell today (checked in code)

| Product | Status | Price | What's built (paths relative to `hebridescyber-app/`) |
|---|---|---|---|
| **Scanner** | Live | Basic £20, Pro £35, Agency £75 a month; 1, 3 and 15 monitored sites (`src/app/pricing/page.tsx`) | Free homepage check with no sign-up (`src/app/check/`); scheduled scans; a findings explorer with triage, KEV and EPSS filters, assignment (migration 078) and team roles (007, 025, 074); a "fix this first" ranking (`estatePriority.ts`); platform fix guides (`platformGuides.ts`); "Check it's fixed" retest; Cyber Essentials and six other framework mappings (`scanners/compliance.ts`); Microsoft 365 posture (`m365Posture.ts`); Google Workspace posture (`workspaceConsent.ts`, dark until OT-58); the weekly "one thing to fix" email (`weeklyFixEmail.ts`); a public security profile and badge (`securityProfile.ts`); API, a CI gate and SARIF export; tickets in Jira, Linear, ServiceNow and GitHub; DMARC report ingestion; emerging-threat alerts (`EmergingThreatsPanel.tsx`) |
| **Lookout** | Pilots by invoice; self-serve checkout in draft #199 | Essentials £149 and Assured £299 a month; quarterly and annual options (`src/app/lookout/page.tsx`) | Analyst-written reports with draft, publish and acknowledge states (`lookoutReports.ts`, migration 075); a dated PDF with an estate screenshot gallery (`lookoutReportPdf.ts`, `estateScreenshots.ts`); lookalike domains (`lookoutLookalikes.ts`); breached email accounts, counts only (`lookoutBreaches.ts`, dark until `HIBP_API_KEY`, OT-17); ATT&CK and CWE mapping; drift between periods (`estateDrift.ts`); customer acknowledgement |
| **Exploit** | Not launched, not marketed (OT-13, OT-51) | None public | Engagement state and scope guard (`exploitability/scope/`, migration 070). Drafts: engagement record with rules of engagement, contacts, windows and expiry (#260); a worker gate enforcing signed scope, window and expiry (#261); an engagement API with atomic abort (#212); "Request validation" on a serious finding (#192) |
| **Phishing awareness** | Design only (`PHISHING-AWARENESS-DESIGN.md`) | To decide (OT-61) | Nothing built. Reuses the M365 and Workspace connections, team roles, report PDFs and email sending |

One leftover to note: `/pricing` still lists three one-off audits (£300,
£800, £1,800), the larger two described as manual testing. That sits awkwardly
with "Exploit isn't marketed" (owner decision 1 below).

## 2. Who we're compared against

| Category | Vendors | What the buyer is buying |
|---|---|---|
| External attack surface management (EASM) | Palo Alto Cortex Xpanse, Microsoft Defender EASM, CrowdStrike Falcon Surface (now part of Falcon Exposure Management), Censys ASM, Mandiant ASM (Google) | "Find everything we have on the internet, before an attacker does" |
| Vulnerability management (VM) | Tenable, Qualys VMDR, Rapid7 InsightVM / Exposure Command | Scanning every asset, inside and out, with agents |
| Security ratings and third-party risk | SecurityScorecard, BitSight, UpGuard | An outside-in grade for yourself and your suppliers |
| SME-facing scanners | Intruder, Detectify, Acunetix (Invicti) | Self-serve web and infrastructure scanning |
| Pentest as a service (PTaaS) | Cobalt, NetSPI, Synack, HackerOne, Bugcrowd | A human-led test, bought through a platform |
| Phishing and awareness | KnowBe4, Proofpoint, Hoxhunt | Simulated phishing and staff training |

Our buyer is not theirs. A UK business with 5 to 100 staff, an agency, or a
developer, usually pushed by Cyber Essentials, an insurer or a customer
questionnaire. Enterprise vendors are still useful to study: they set buyers'
expectations, and their ideas reach the SME market a few years later.

## 3. Feature matrices

Key: **Yes** = built (ours) or reported (theirs). **Partial** = some of it, or
built but dark until an owner step. **No** = not built (ours). **n/f** = not
found in these searches (theirs).

### 3.1 Scanner against EASM, VM, ratings and SME scanners

| Capability | Hebrides Scanner | EASM | VM | Ratings | SME scanners |
|---|---|---|---|---|---|
| Free entry point | **Yes**: instant check, no sign-up | Defender EASM 30-day trial [E1]; Censys free tier [E4] | Qualys Community Edition reported [E7] | SecurityScorecard free self-rating, A–F across 10 factors [E9] | Intruder free plan reported [E12] |
| Public price | **Yes**, £20–£75 a month | Defender EASM per asset per day, rate not shown on Microsoft's page [E1]; others quote-only [E2, E4, E5] | Tenable online to 250 assets; Rapid7 "from" price; Qualys quote [E6–E8] | Paid tiers quote-only [E9–E11] | Partly public; aggregators disagree [E12–E14] |
| Discovery from a seed domain | **Yes**: certificate logs and passive subdomain discovery on every scan, a 6-hourly sweep, new-host alerts | **Yes**, the core product | Nessus Expert adds external discovery [E6] | **Yes**, as an input to the rating | Intruder and Detectify **Yes** [E12, E13] |
| Internet-wide mapping and attribution (finding assets the customer didn't list, by organisation) | **No**: we start from domains the customer gives us | **Yes**: CrowdStrike says it maps the internet continuously [E3]; Xpanse "actively discover" [E2] | n/f | **Yes**, it's how ratings find a company's assets | n/f |
| Web application scanning, including signed-in | **Yes**; signed-in on Agency | n/f | Tenable (Nessus Expert) **Yes** [E6] | n/f | **Yes**: Detectify, Acunetix [E13, E14] |
| CVEs on exposed services | **Yes**, external only | **Yes** | **Yes**, the core product | Partial (signals feed the grade) | **Yes** |
| Internal networks and devices (agent) | **No** | No (external by definition) [E2] | **Yes**, the core product | No | Intruder internal on Pro and up [E12] |
| Exploit and likelihood signals | **Yes**: KEV and EPSS filters, public-exploit flags, "confirmed exploitable" | CrowdStrike adversary intelligence [E3] | **Yes** | n/f | Partial |
| Response when a new vulnerability is disclosed | **Yes**: emerging-threat alerts | n/f | n/f | n/f | Intruder runs checks automatically on disclosure [E12] |
| One prioritised list | **Yes**: "fix this first", with reasons | **Yes** [E3] | **Yes** | **Yes**, by grade impact | Intruder **Yes** [E12] |
| Grade and "what if I fix this" planner | Grade **Yes**; planner **No** | n/f | n/f | SecurityScorecard Score Planner [E9] | n/f |
| Email authentication and DMARC reports | **Yes** | n/f | n/f | Partial (a rating factor) | Partial |
| Microsoft 365 and Google Workspace posture | **Yes** M365; **Partial** Workspace (OT-58) | n/f | Rapid7 counts identities as billable assets [E8] | n/f | n/f |
| Platform-specific fix guides (WordPress, Shopify, M365 DNS and others) | **Yes** | n/f | n/f | n/f | n/f |
| Retest one finding on demand | **Yes** | n/f | n/f | n/f | Intruder (`IMPROVEMENT-REVIEW-2026-11.md`) |
| Workflow: triage, assign, teams, tickets, SLAs | **Yes** | **Yes**: ticketing, SOAR, ServiceNow [E3, E5] | **Yes** | Action Plans with vendors [E9] | **Yes** |
| CI gate and API | **Yes** | API **Yes** | API **Yes** | API **Yes** | **Yes** |
| Compliance mapping | **Yes**: Cyber Essentials, ISO 27001, CIS, PCI, NIS2, DORA, OWASP | n/f | **Yes** | Partial | Partial |
| Weekly "one thing to fix" email | **Yes** | n/f | n/f | n/f | n/f |
| Public trust page and badge | **Yes** (grade, last check, passing practices) | n/f | n/f | UpGuard Trust Exchange, priced until early 2026 [E10] | n/f |
| Used by insurers | Mapping and wording only | n/f | n/f | BitSight data is used in insurer models (Allianz; Moody's RMS) [E11] | n/f |

### 3.2 Lookout against managed EASM, threat intelligence and ratings

| Capability | Lookout | Enterprise EASM and intelligence | Ratings |
|---|---|---|---|
| Report written by a named engineer | **Yes**: a draft is pre-filled from the ranking and drift; the analyst edits and publishes | n/f for small buyers. Hadrian sells a managed service at about $50,000 for 250 assets (`COMPETITIVE-REVIEW-2026-11.md` S8) | No, it's a platform |
| Dated PDF and portal page | **Yes** | Platform reports | **Yes**, board reports |
| Customer acknowledgement | **Yes** ("I've read this report") | n/f | Vendor Action Plans [E9] |
| Estate screenshots | **Yes** | n/f | n/f |
| Lookalike domains | **Yes** | Mandiant Digital Threat Monitoring, now inside Google Threat Intelligence Enterprise [E5] | n/f |
| Breached accounts | **Partial**: built, dark until HIBP (OT-17) | CrowdStrike Falcon Intelligence Recon for the dark web [E3] | n/f |
| Dark-web and brand monitoring beyond breaches | **No** | **Yes** [E3, E5] | n/f |
| ATT&CK mapping | **Yes** | **Yes** | n/f |
| Automatic response (playbooks) | **No** | Xpanse with XSOAR [E2] | n/f |
| Trend over time | Drift between periods; no chart in the report | **Yes** | **Yes**: rating history is the core view |
| Supplier monitoring | **No** | n/f | **Yes**, the core product: UpGuard Vendor Risk from about $1,599 a month [E10] |
| Public price | **Yes**, £149 / £299 a month | No: Xpanse reported around $95,000 a year [E2]; Mandiant priced by employee count [E5] | No [E9–E11] |

### 3.3 Exploit against PTaaS

| Capability | Exploit (not launched) | Cobalt | NetSPI | Synack | HackerOne / Bugcrowd |
|---|---|---|---|---|---|
| Who tests | The founder | Pentest team through the platform [E15] | Full-time employees [E16] | Vetted red team of about 1,500, plus an AI agent [E17] | Researcher network [E18] |
| Scope, window and expiry enforced by the tooling, not only the contract | **Partial**: guard merged; gate in draft #261 | n/f | n/f | n/f | n/f |
| Customer stop button | **Partial**: atomic abort in draft #212 | n/f | n/f | n/f | n/f |
| Time to start | By hand, after a signed scope | "Within 24 hours"; network tests 1–3 business days [E15] | n/f | n/f | n/f |
| Live channel with testers | **No** | Slack or Teams channel per test [E15] | n/f | n/f | n/f |
| Findings into the customer's tracker during the test | **Partial**: Scanner's ticket integrations exist; not wired to engagements | **Yes**: Jira, GitHub, Slack and 50+ tools [E15] | Resolve platform [E16] | n/f | n/f |
| Retest included | **No** (not designed yet) | 6 or 12 months of retests; pages differ [E15] | n/f | n/f | n/f |
| AI or autonomous testing | **No**: out of version 1 (OT-53) | Autonomous Pentest, 2026 [E15] | n/f | Sara agent; trial offered [E17] | "Agentic PTaaS" [E18] |
| Starts from existing scanner evidence | **Partial**: "Request validation" in draft #192 | n/f | Asset discovery in plans [E16] | n/f | n/f |
| Accreditation (CREST and similar) | **No** (owner decision 3) | n/f | n/f | n/f | n/f |
| Price | None public | $3,500-a-test promotion to 31 Dec 2026; credit tiers quote-only [E15] | Not published [E16] | Sara pentest from about $4,181 (competitor-reported) [E17] | Small test estimated $10,000–$15,000 [E18]; Bugcrowd not published [E17] |

### 3.4 Phishing awareness (planned) against awareness platforms

| Capability | Our design | KnowBe4 | Proofpoint | Hoxhunt |
|---|---|---|---|---|
| Free baseline test | Not planned | **Yes**: free Phishing Security Test, PDF with an industry benchmark in about 24 hours [E19] | n/f | n/f |
| Headline measure | **Reporting rate**, clicks second (design §3) | Phish-prone percentage; 34.3% industry baseline in its 2024 data [E19] | n/f | Reporting rate; claims a 225% rise in reports [E20] |
| One-click report button | Phase 3 | n/f | n/f | **Yes**: Outlook and Gmail, desktop and mobile [E20] |
| Difficulty adapts per person | No | n/f | n/f | **Yes** [E20] |
| Gamification and leaderboards | Deliberately no individual league table (D6) | n/f | n/f | **Yes**: stars, streaks, leaderboards [E20] |
| Credentials captured | **Never**, by design | n/f | n/f | n/f |
| Bundled with something else | Lookout report, Scanner, M365 and Workspace connections | n/f | Cheap add-on to its email security [E20] | n/f |
| Price | To decide (£1–£3 per user a month considered) | About $0.90–$2.35 per user a month at list, 25-seat minimum, sources disagree; may have moved to two tiers [E19] | About $2–$4 per user a month standalone, less when bundled [E20] | About $10,000 a year minimum reported [E20] |

## 4. Stronger, at parity, missing

### Where we are stronger

1. **Plain English for one owner.** The weekly "one thing to fix" email,
   platform fix guides and a single "fix this first" list. Enterprise tools
   assume a security team triaging thousands of assets. Nothing comparable
   turned up for any enterprise vendor.
2. **A published price at small-business scale.** Every EASM, ratings and
   PTaaS vendor here is quote-only or priced per asset or per employee
   [E1–E5, E9–E11, E15–E18]. Xpanse is reported at about $95,000 a year [E2].
   Lookout at £149 a month with a named engineer has no visible equivalent.
3. **Scanner, managed review and test in one body of evidence** (the
   ladder). The large vendors sell these as separate products. The only ones
   that combine scanning and testing are platform suites (Rapid7, Tenable)
   aimed at security teams.
4. **Cloud mail posture without agents.** M365 posture, Workspace posture
   (dark until OT-58) and DMARC ingestion. In this category set, only
   Rapid7's asset model mentions identities [E8].
5. **Scope enforced in code for Exploit.** Signed scope, window, expiry and
   abort are checked by the worker, not only in the contract. No PTaaS source
   described this, so it's a selling point for a first-time, nervous buyer,
   once OT-13 is done.
6. **Safety by design in phishing.** No credentials captured, reporting rate
   first, no individual league table. That follows the NCSC's line and the
   ETH Zurich study (design §3). It's a credible way in where some buyers
   find gamified leaderboards uncomfortable.

### At parity (for our buyer)

- External discovery from a seed domain, new-host alerts, takeover and lookalike checks.
- Web, API and signed-in scanning; CVEs on exposed services; KEV and EPSS.
- Workflow: triage, assignment, teams, tickets, SLAs, CI gate, API, SARIF.
- Emerging-threat alerts (Intruder positions the same thing [E12]).
- A–F grade and public badge (SecurityScorecard and UpGuard have the enterprise versions).
- Compliance mapping, worded as an indicator, never a certification.

### Missing, and whether it matters

| Gap | Who has it | Matters for our buyer? |
|---|---|---|
| A "what if I fix these" grade planner | SecurityScorecard [E9] | **Yes.** Cheap to build, and it turns a grade into a plan (idea 1) |
| Sector comparison ("how do you compare?") | KnowBe4 benchmarks [E19]; ratings vendors | **Yes**, for the free check funnel and reports (idea 4) |
| Evidence packaged for insurers | BitSight data in insurer models [E11] | **Yes**: insurers are our trigger. A generated pack, not a rating (idea 2) |
| Score and posture trend charts in reports | Ratings vendors | **Yes**: owners want to see progress (idea 7) |
| Internet-wide attribution (assets the customer forgot to list) | EASM vendors [E2, E3] | **Partly.** A light version from connected tenants' verified domains is cheap (idea 6) |
| Dark-web and brand monitoring beyond breaches | CrowdStrike Recon, Mandiant DTM [E3, E5] | Low for now; HIBP covers the commonest case |
| Supplier monitoring | UpGuard, SecurityScorecard, BitSight [E9–E11] | Medium. SMEs are asked about suppliers; agencies could sell it (idea 12) |
| Live tester channel, findings during the test, included retests | Cobalt [E15] | **Yes for Exploit**, after OT-13 (idea 10) |
| One-click report button, adaptive difficulty | Hoxhunt [E20] | Later (phase 3 of the phishing design) |
| Internal agents | VM vendors | Only for Cyber Essentials Plus device checks (`ENTERPRISE-GAP-ANALYSIS.md` P1-5). Don't chase |
| Platform certification (SOC 2, ISO 27001) | All of them | Our own Cyber Essentials first (no OT item yet; OT-38 to OT-41 cover SOC 2 or ISO 27001, which can wait) |
| CREST-style accreditation for tests | UK test firms | Owner decision 3 |

## 5. Pricing and packaging lessons

| Vendor | Unit | Reported figure | Confidence |
|---|---|---|---|
| Microsoft Defender EASM | Per billable asset per day; 30-day trial | About $0.011 a day (around $4 a year) per asset, or $0.017 in another source; Microsoft's page shows no rate [E1] | Low (rate); High (model, from Microsoft Learn) |
| Cortex Xpanse | Per asset band | About $95,000 a year for up to 999 assets [E2] | Low |
| Censys ASM | Assets under management; credits for search | Around $5,000 a year entry, unconfirmed [E4] | Low |
| Mandiant ASM | Per employee, plus a base fee | Not public [E5] | High (model, Google's page) |
| Tenable | Per asset; online sales only to 250 assets | About $37 per asset a year online; Nessus Expert about $6,790 a year [E6] | Low-medium |
| Qualys VMDR | Per asset | $199 per asset a year in one source, $20–$40 per IP in another [E7] | Low |
| Rapid7 InsightVM | Per asset per month | From $1.62 per asset a month at 500 assets [E8] | Medium |
| SecurityScorecard | Free self-rating; paid by quote | Paid from about $15,000–$20,000 a year, unofficial [E9] | High (free tier); Low (paid) |
| UpGuard | Employee bands (Breach Risk); vendor count (Vendor Risk) | Breach Risk was from $250 a month and dropped from the page in early 2026; Vendor Risk Starter $1,599 a month [E10] | Medium |
| BitSight | Quote | $20,000 to $250,000+ a year, sources disagree [E11] | Low |
| Intruder | Base plus per target; free tier | Essential about $99–$149 a month; Cloud $180–$299 [E12] | Low |
| Detectify | Per domain and per target | About $90 a month (app) and $302 a month (25 assets), possibly outdated [E13] | Low |
| Acunetix / Invicti | Per FQDN, 5-target minimum | Roughly $4,500–$7,000 a year to start [E14] | Low |
| Cobalt | Credits; per-test promotion | $3,500 a test to 31 Dec 2026 [E15] | High (Cobalt's page) |
| KnowBe4 | Per user, 25-seat minimum | About $0.90–$2.35 per user a month [E19] | Low |
| Proofpoint SAT | Per user | About $2–$4 per user a month standalone [E20] | Low |
| Hoxhunt | Quote | About $10,000 a year minimum [E20] | Low |

**Lessons:**

1. **Published, flat prices are our wedge. Keep them.** Above the SME
   scanners, everyone is quote-only. Even UpGuard took its small-business
   price off its page in 2026 [E10]. Don't drift towards "contact us" for
   Lookout or Exploit.
2. **Unit definitions surprise buyers.** Rapid7's billable assets now include
   identities and cloud workloads [E8]. Defender EASM bills any host that
   resolved in the last 30 days [E1]. Acunetix counts each subdomain and port
   [E14]. Our "monitored sites" unit is simple: say in one line what counts,
   and show usage against the cap (idea 9).
3. **A free tier you can keep is the norm at the top**, not just a trial:
   SecurityScorecard's free self-rating [E9], KnowBe4's free test [E19],
   Qualys Community Edition [E7]. Our free check is the right shape. Making
   the free result re-checkable and comparable (ideas 1 and 4) pulls people
   back.
4. **PTaaS is moving to fixed per-test prices for small buyers.** Cobalt
   advertises $3,500 a test [E15], and Synack offers a free AI pentest trial
   [E17]. A published fixed-scope Exploit package, after OT-13 and a manual
   pilot (OT-54), would be in step with the market, not against it.
5. **Awareness training gets bundled.** Proofpoint sells it as a cheap add-on
   to email security [E20]. Standalone, we'd compete with KnowBe4 at about
   $1–$2 per user. Included in Lookout, it's a reason to buy Lookout. That
   supports the design's D9 recommendation.
6. **Sell outcomes, not seats, at the small end.** Mandiant prices by employee
   count [E5], and UpGuard did by employee band [E10]. An SME understands
   "businesses up to 50 staff" better than "assets". Worth considering for
   Lookout tiers (owner decision 4).

## 6. UX, onboarding and reporting patterns worth borrowing

| Pattern | Seen at | How we'd use it |
|---|---|---|
| **"What if" planner**: drag issues into a plan, see the new grade; or generate the plan for a target grade | SecurityScorecard Score Planner [E9] | Idea 1. Feeds the weekly email ("fix these three to reach a B") |
| **Benchmark on the free result**: your number against your industry | KnowBe4 test PDF [E19] | Idea 4, on `/check` and in reports, once there's enough data |
| **Notify on disclosure, quiet otherwise** | Intruder [E12] | Already have emerging-threat alerts; add "only tell me about new" (idea 5) |
| **Collaborative plans with a third party** | SecurityScorecard Action Plans [E9] | Agencies and IT suppliers share a fix plan with their client: the Agency tier's natural workflow (idea 8) |
| **Start in 24 hours, a channel per engagement, findings as they're found** | Cobalt [E15] | Exploit delivery (idea 10) |
| **Interactive product tour without sign-up** | Hoxhunt [E20] | A clickable sample Lookout report with synthetic data (idea 11). `/sample-reports` exists for Scanner |
| **Reporting rate as the headline** | Hoxhunt [E20] | Already the design's choice, so keep it |
| **Ratings history as the main chart** | Ratings vendors | Trend charts in the Lookout report and Agency portfolio (idea 7) |
| **Seed discovery from what the customer already connected** | Defender EASM's inventory model [E1] | Suggest monitored sites from an M365 tenant's verified domains, already read by `m365Posture.ts` (idea 6) |

## 7. Ranked ideas

Ranked by value to our buyer for the effort, at launch, for a solo founder.
Effort: **S** is under 3 days, **M** is about 1–2 weeks, **L** is over 2 weeks.

| # | Idea | Product | Benefit | Effort | Depends on |
|---|---|---|---|---|---|
| 1 | **Grade planner.** On the report and dashboard: tick findings and see the projected grade; "get me to a B" picks the fewest fixes. The weekly email can say "two fixes to a B" | Scanner | Turns a grade into a short plan; the same motivation as the badge. Pattern from SecurityScorecard [E9] | S–M | Grading is deterministic from findings, so it needs a pure "score without these findings" function |
| 2 | **Insurer and questionnaire evidence pack.** One PDF: grade and trend, Cyber Essentials mapping, M365 or Workspace posture, email authentication, breach exposure (when HIBP is on), the open-findings plan, dated and labelled "evidence, not certification" | Scanner Pro and up; Lookout | Answers the trigger that brings buyers in (insurers, supplier questionnaires). Lookout already lists it as a quoted extra; generating it makes it repeatable | M | Existing PDFs; wording checked under OT-35 |
| 3 | **Lookalike-domain response kit.** For each lookalike: what it means, an abuse-report template for the registrar or host, and steps to block it in M365 or Workspace | Lookout; Scanner alerts | Today we tell the owner about a lookalike but not what to do. Enterprise tools automate response [E2] | S | Static content plus the existing lookalike data |
| 4 | **"How you compare" benchmark** on `/check` results and reports: your grade against UK small businesses, and by sector where there's data (we have sector pages) | Scanner (funnel) | A reason to act and to share; KnowBe4's free test is built on it [E19] | M | Aggregate free-check and scan results; hide until each group has enough results; privacy notice wording (owner decision 6) |
| 5 | **Quiet-by-default alerts**: a "first seen" column in the findings explorer and an alert setting "only tell me about new findings" | Scanner | Less noise, the thing Intruder markets [E12]. `first_seen` data exists | S | None |
| 6 | **Suggest sites from connected tenants.** After M365 or Workspace consent, list the tenant's verified domains that aren't monitored yet, with one-click add (verification still applies) | Scanner; Lookout | A light version of EASM attribution: finds the forgotten domain without internet-wide mapping | S–M | `m365Posture.ts` already reads `/domains`; Workspace needs OT-58 |
| 7 | **Trend charts in the Lookout report and Agency portfolio**: grade, open findings by severity, and time to fix, quarter on quarter | Lookout; Scanner Agency | Shows progress, which is what a renewal rests on. Ratings vendors lead with history | S–M | `estateDrift.ts` and score history exist |
| 8 | **Shared fix plan** for agencies and IT suppliers: an Agency user shares a read-only plan for one client's site with the client's contact, who can mark items done (each item retested) | Scanner Agency | Agencies sell our report as their service; the pattern behind SecurityScorecard's Action Plans [E9] | M | Team invites (074) and retest |
| 9 | **Usage and "what counts" clarity**: show sites used against the plan cap in the dashboard, with one line on the pricing page explaining what a monitored site is | Scanner | Avoids the asset-count surprises buyers complain about elsewhere [E1, E8, E14] | S | None |
| 10 | **Exploit delivery pack**: a channel per engagement (email thread or Teams), findings pushed to the customer's tracker as confirmed through the existing ticket integrations, a retest window, and an attestation letter after the retest | Exploit | Matches the PTaaS norm [E15] at small-buyer scale; the letter is what insurers and procurement actually ask for | M | **After OT-13 and OT-51**; #260, #261, #212 merged first. Governance and delivery only, no new testing capability |
| 11 | **Interactive sample Lookout report** on `/lookout`, with synthetic, clearly labelled data | Lookout | Lets a prospect see the "named engineer" value before a call; Hoxhunt-style tour [E20] | S | Lookout name cleared (OT-33) before public ads |
| 12 | **Supplier watch (light)**: Assured or Agency customers list up to 10 suppliers' domains; we run only public-record checks (mail authentication, certificate and TLS facts, breach counts) and report a grade, never active scanning | Lookout Assured; Scanner Agency | Answers "how do you manage supplier risk?" on questionnaires, at a fraction of UpGuard Vendor Risk's $1,599 a month [E10] | M | Owner decision 5 (legal view on grading third parties without their consent); passive only |
| 13 | **Phishing awareness phase 1 inside Lookout**: managed quarterly campaign, reporting rate as the headline, results as a Lookout report section | Phishing; Lookout | Bundling beats competing with KnowBe4 on per-seat price [E19, E20]; gives Assured a clear extra | L | OT-59, OT-60, OT-61; design D1 to D9 |
| 14 | **Trust page documents**: the public security profile can also offer documents (a Cyber Essentials certificate, a policy) shared on request by email | Scanner | Turns the badge into a small trust centre. UpGuard Trust Exchange was priced from $600 a month until early 2026 [E10] | M | Storage bucket pattern from estate screenshots; abuse controls |

**If only three get built before the first paid Lookout renewals:** 1 (grade
planner), 2 (evidence pack) and 3 (lookalike kit). All three use data we
already have, and each answers the question the buyer arrived with.

Already proposed elsewhere and still valid, so not repeated above: the public
accuracy benchmark and "what every plan sends" page (`COMPETITIVE-REVIEW-2026-11.md`
bets 2 and 5), and the Cyber Essentials Plus readiness pack (bet 4).

## 8. Owner decisions (not code)

| # | Decision | Recommendation |
|---|---|---|
| 1 | The one-off "manual pen test" audits on `/pricing` (£800, £1,800) while Exploit isn't marketed | Remove or reword as automated audits until OT-13 and OT-51 clear (also flagged in `IMPROVEMENT-REVIEW-2026-11.md` UX fix 3) |
| 2 | Keep every price public, including Lookout and a future Exploit package | Yes. It's the clearest difference from every enterprise vendor here |
| 3 | Accreditation route for Exploit: CREST-style accreditation, a partner who countersigns, or neither at first | Partner first (`COMPETITIVE-REVIEW-2026-11.md` decision 1) |
| 4 | Lookout tiers by staff count ("up to 50 staff") as well as by domains and IPs | Consider at the OT-42 review; test the wording with pilot customers |
| 5 | Supplier watch (idea 12): is grading a third party from public records acceptable to us and our solicitor? | Ask under OT-35 before building |
| 6 | Using anonymised, aggregated scan results for benchmarks (idea 4) | Yes, with a privacy-notice line and a minimum group size |
| 7 | Phishing packaging (design D9) | Included in Lookout Assured first; self-serve add-on later |
| 8 | A 14-day Pro trial alongside the free check (SecurityScorecard and Defender EASM run trials [E1, E9]) | Try it after the first 40 sign-ups, so the effect can be measured |
| 9 | Our own Cyber Essentials certification (a candidate OT item; OT-38 to OT-41 cover the bigger SOC 2 or ISO 27001 route) | Do it before Lookout ads: every enterprise rival is certified, and we sell Cyber Essentials help |

## 9. What not to do

- Don't build internet-wide scanning and attribution to match Xpanse or
  CrowdStrike. It's a data business. Idea 6 gets most of the value for our
  buyer.
- Don't build an internal-agent VM product to match Tenable, Qualys or
  Rapid7. The only case is Cyber Essentials Plus devices, and the CE+
  readiness pack plus a certification-body partner comes first.
- Don't claim 24/7 monitoring, a SOC, an SLA or certifications we don't hold.
- Don't build gamified leaderboards or individual shaming in the phishing
  product, whatever Hoxhunt does. It goes against our own design principles.
- Don't add autonomous testing to Exploit version 1 (OT-53), however much
  the PTaaS vendors push it [E15, E17, E18].

## Sources

All retrieved by web search on 2026-11-20. "Vendor page" means the vendor's
own site appeared in the results. None of the pages were opened directly, so
every figure needs re-checking before use outside this repo.

- **E1** Microsoft Defender EASM: [Azure pricing page](https://azure.microsoft.com/pricing/details/defender-external-attack-surface-management/) (vendor page; rate fields blank), [Understand billable assets](https://learn.microsoft.com/en-sg/azure/external-attack-surface-management/understanding-billable-assets) (vendor), [Tenable CIS audit item](https://www.tenable.com/audits/items/CIS_Microsoft_Azure_Foundations_v4.0.0_L2.audit:aa58cea0d1e7df98a999b8d82e3459d9)
- **E2** Cortex Xpanse: [CyCognito overview](https://www.cycognito.com/learn/attack-surface/cortex-xpanse) (competitor), [Compliance Stronghold review](https://compliancestronghold.pages.dev/reviews/cortex-xpanse), [UpGuard competitor page](https://www.upguard.com/competitors/cortex-xpanse.md) (competitor)
- **E3** CrowdStrike Falcon Surface: [press release](https://www.crowdstrike.com/press-releases/crowdstrike-expands-falcon-platform-with-external-attack-surface-management-technology/) (vendor), [Falcon Exposure Management data sheet](https://www.crowdstrike.com/content/dam/crowdstrike/marketing/en-us/documents/pdfs/data-sheets/falcon-exposure-management-data-sheet.pdf) (vendor)
- **E4** Censys: [pricing](https://censys.com/pricing/) (vendor), [ethicalhacking.ai](https://ethicalhacking.ai/pricing/censys-asm-pricing), [G2](https://www.g2.com/products/censys-attack-surface-management/pricing)
- **E5** Mandiant ASM: [Google Cloud product page](https://cloud.google.com/security/products/attack-surface-management) (vendor), [BitSight vs Mandiant guide](https://www.bitsight.com/guides/bitsight-vs-mandiant-google-threat-intelligence-2026) (competitor)
- **E6** Tenable: [cipherssecurity Nessus pricing](https://cipherssecurity.com/tenable-nessus-pricing-2026-editions-costs/), [CostBench](https://costbench.com/software/vulnerability-management/tenable/), [Tenable One licensing guide](https://docs.tenable.com/quick-reference/licensing-guide/Content/tenable-one-licensing.htm) (vendor)
- **E7** Qualys: [Beagle Security](https://beaglesecurity.com/blog/article/qualys-pricing.html), [Vendor Benchmark](https://vendorbenchmark.com/vendors/qualys-pricing), [UnderDefense](https://underdefense.com/industry-pricings/qualys-pricing-ultimate-guide-for-security-products)
- **E8** Rapid7: [cipherssecurity InsightVM pricing](https://cipherssecurity.com/rapid7-insightvm-pricing-2026-cost-per-asset/), [Beagle Security](https://beaglesecurity.com/blog/article/rapid7-pricing.html)
- **E9** SecurityScorecard: [pricing and packages](https://securityscorecard.com/pricing-packages/) (vendor), [What is the Score Planner?](https://support.securityscorecard.com/hc/en-us/articles/360056399091) (vendor), [Action Plans](https://support.securityscorecard.com/hc/en-us/articles/24668863084315-Vendor-invitation-How-and-why-to-participate-in-an-Action-Plan) (vendor), [Capterra](https://www.capterra.com/p/172806/SecurityScorecard/pricing/)
- **E10** UpGuard: [PricingSaaS change log, 2026 W10](https://pricingsaas.com/companies/upguard/diffs/2026W10), [Orbiq comparison](https://www.orbiqhq.com/comparisons/upguard-pricing), [Software Advice](https://www.softwareadvice.com/product/471657-UpGuard/)
- **E11** BitSight: [Vendr](https://www.vendr.com/marketplace/bitsight), [BitSight and Kovrr press release](https://www.bitsight.com/press-releases/bitsight-and-kovrr-announce-financial-quantification-for-enterprise-cyber-risk) (vendor), [Moody's RMS cyber version 9](https://www.moodys.com/web/en/us/insights/insurance/introducing-moodys-rms-cyber-solutions-version-9.html)
- **E12** Intruder: [pricing](https://www.intruder.io/pricing) (vendor), [Beagle Security](https://beaglesecurity.com/blog/article/intruder-pricing.html), [cipherssecurity](https://cipherssecurity.com/intruder-io-pricing-plans-scan-costs/), [emerging threat scanning](https://www.intruder.io/use-cases/emerging-threat-scanning) (vendor), [attack surface monitoring](https://www.intruder.io/use-cases/attack-surface-monitoring) (vendor)
- **E13** Detectify: [Beagle Security](https://beaglesecurity.com/blog/article/detectify-pricing.html), [cipherssecurity](https://cipherssecurity.com/detectify-pricing-alternatives-2026/)
- **E14** Acunetix / Invicti: [AppSecSanta](https://appsecsanta.com/invicti-vs-acunetix), [cipherssecurity](https://cipherssecurity.com/acunetix-pricing-2026/), [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-cene4t3k5k5wm)
- **E15** Cobalt: [pricing](https://www.cobalt.io/platform/pricing) (vendor), [pentest platform](https://www.cobalt.io/pentest-security-platform) (vendor), [get started (SMB)](https://www.cobalt.io/get-started-smb) (vendor), [Autonomous Pentest press release](https://www.cobalt.io/press-release/cobalt-launches-autonomous-pentest-to-bolster-continuous-security-testing-across-the-full-application-portfolio-1) (vendor)
- **E16** NetSPI: [PTaaS plans](https://www.netspi.com/plans) (vendor), [Vendr](https://www.vendr.com/marketplace/netspi)
- **E17** Synack and Bugcrowd: [Stingrai PTaaS pricing compared](https://www.stingrai.io/blog/ptaas-pricing-compared-2026) (competitor), [Synack on Cobalt pricing](https://www.synack.com/?p=27342) (competitor)
- **E18** HackerOne: [Stingrai](https://www.stingrai.io/blog/hackerone-pentest-pricing-2026) (competitor), [Spendflo](https://www.spendflo.com/blog/hackerone-pricing-guide)
- **E19** KnowBe4: [Phishing Security Test](https://info.knowbe4.com/phishing-security-test) (vendor), [benchmark press release](https://www.knowbe4.com/press/knowbe4-unveils-new-phishing-benchmark-data-and-showcases-most-at-risk-industries) (vendor), [TrustRadius](https://trustradius.com/compare-products/knowbe4), [CGNET on new licensing](https://cgnet.com/blog/knowbe4s-new-licensing-simplified/)
- **E20** Proofpoint and Hoxhunt: [RansomLeak pricing guide](https://ransomleak.com/blog/security-awareness-training-pricing/), [Hoxhunt phishing training](https://hoxhunt.com/product/phishing-training) (vendor), [Hoxhunt on Frost & Sullivan](https://www.hoxhunt.com/blog/managing-human-risk-in-cybersecurity-frost-sullivan-report) (vendor), [Hoxhunt interactive tour](https://hoxhunt.com/interactive-platform-tour) (vendor)

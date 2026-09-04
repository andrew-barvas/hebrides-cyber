# Marketing Plan — First 6 Months

**For platform-specific social media setup (LinkedIn/Facebook/X bios,
content calendar, local press outreach), see
`11-social-media-and-local-press-playbook.md`** — that doc owns the
tactical how; this one owns channel priority and KPIs, not duplicated
between them.

**Rewritten 2026-08-28** — the original draft predated real product state: it
assumed manual blog posting (the daily-blog + weekly-newsletter pipeline is
now automated — see `hebridescyber-app/docs/architecture.md`), had no KPI
actually tracked against it, and didn't reflect the positioning conclusion in
`hebridescyber-app/docs/COMPETITIVE-ANALYSIS.md` §9. This version replaces
it rather than patching it — the channel prioritisation below follows from
that analysis, not from a fresh brainstorm.

## Before spending on any paid or high-effort channel: fix the funnel

`hebridescyber-app/docs/ENHANCEMENTS.md` **E-07** — `STRIPE_PRICE_BASIC`/
`PRO`/`AGENCY` are unset in production, so **Stripe Checkout 400s/500s on
every plan today**. Every tactic below that drives traffic to a paid signup
(paid ads, cold outreach, case studies) is wasted spend until this is fixed —
it's a Stripe Dashboard + Azure app-settings task, not a marketing one, but
it blocks marketing regardless. Confirm this is resolved before spending a
pound on Google Ads.

## Positioning (from the competitive analysis — don't drift from this)

**Developer-and-agency-friendly automated scanner for UK SMEs with a
compliance trigger** (Cyber Essentials, a client/insurer/procurement
requirement, a recent scare) — not a 24/7 MDR provider, not an enterprise
platform. Every genuine differentiator below is checked against the code,
not aspirational copy:

- **New/Fixed diffing at £20/month** — most tools in this price band
  re-report every finding every scan; competitors' cheapest tiers rarely do
  this at all.
- **Four-rung remediation ladder** — generic text → AI-tailored fix → ticket
  creation with dedupe → a real merged PR for safe dependency bumps. This is
  the single best demo asset in the product; lead with it.
- **Cyber Essentials mapping as a first-class output** — genuinely
  differentiated for UK SMEs specifically; most head-on competitors are
  US-headquartered and don't lead with this.
- **CI gate scoped to newly-introduced findings only** — a real technical
  answer to "security gates get disabled after day one," worth a technical
  audience's attention on its own.

**Do not lead with**: 24/7 monitoring, incident-response SLAs, enterprise
compliance (SOC 2/ISO 27001), or anything implying team-scale support — see
`COMPETITIVE-ANALYSIS.md` §6(c) for why these are structurally off the table
for a solo operator, and §8 for anti-features not to build toward.

## Objectives

- Get the paid funnel actually working (E-07), then acquire the first 20
  paying customers.
- Build the case-study/proof-of-work asset library the developer/agency
  channels below depend on — currently zero real customer stories exist,
  which blocks those channels more than any tactic does.
- Establish the Cyber Essentials / UK-SME compliance angle as the primary
  lead-generation trigger, not generic "get a security scan."

## Channels & Tactics, in priority order

### 1. Content & SEO (ongoing, lowest marginal cost — already partly built)

The daily blog and weekly newsletter (`generate-daily-blog.ts`/
`generate-weekly-newsletter.ts`, real CVE/KEV-sourced content, already
running in production) is a real, running asset the original plan didn't
know about — use it, don't duplicate it with a manual content calendar.

- Add 1-2 **evergreen, non-automated** pieces a month that the AI pipeline
  won't produce on its own: "What Cyber Essentials actually checks vs. what
  we check," a worked remediation-PR walkthrough, a New/Fixed-diff case
  study once real customer data exists (with permission).
- Turn `/what-we-check` and the Security Score one-page report into the
  primary SEO-friendly lead magnet — it already exists in the product,
  doesn't need new content work, just needs a distribution push (submit to
  relevant UK small-business/compliance directories, link from local
  outreach below).
- Local landing pages ("Security for Hebrides tourism sites," "Security for
  churches in Lewis") — keep from the original plan, low effort, genuine
  local differentiation, no dependency on anything unbuilt.

### 2. Cyber Essentials / compliance-triggered outreach (primary lead gen)

This replaces the original plan's generic "local outreach" framing with the
actual differentiated angle from the competitive analysis.

- Direct outreach to businesses who *need* Cyber Essentials for procurement
  (local government/NHS/tourism-board suppliers commonly require it) —
  lead with the CE-mapping output specifically, not a generic "free scan"
  offer.
- Partner with local Cyber Essentials assessors/IASME-affiliated advisors as
  a referral channel — they see the compliance-trigger customer first and
  don't offer ongoing automated monitoring themselves.
- Local business groups/chambers talk, framed around "what Cyber Essentials
  actually requires vs. what most site owners assume" — a genuinely useful
  talk, not a sales pitch, that naturally surfaces leads.

### 3. Developer & agency channels (needs #1's proof-of-work first)

- Technical before/after threads built around the remediation ladder
  specifically (a real merged PR fixing a real dependency CVE is a strong,
  concrete post) — X/Twitter, LinkedIn, relevant subreddits.
- Case studies on Hacker News/Indie Hackers — **blocked until real paying
  customers exist and consent to being named**; don't force this before
  there's real material, a thin/fake-feeling case study actively hurts
  developer-audience credibility.
- Agency partnerships: white-label PDF reports (already shipped, Agency
  tier) is the concrete pitch — "resell Security Score reports under your
  own brand" is a complete, demoable offer today.

### 4. Paid & partnerships (only after #1-3 have organic signal)

- Small Google Ads test (£200/mo) on "Cyber Essentials readiness check UK"
  and similar compliance-intent terms, not generic "security audit" —
  higher intent, smaller and cheaper keyword set, matches the positioning
  above. **Do not start this until E-07 is confirmed fixed.**
- Hosting provider / local ISP referral partnerships — keep from the
  original plan, unchanged.

### 5. Retention (unchanged from original plan, still sound)

- Monthly newsletter with security tips and client highlights (distinct
  from the automated weekly security-news newsletter — this one is
  relationship-focused, not content-pipeline-generated).
- Quarterly "security for small teams" webinar once there's a customer base
  large enough to make one worth running.

## KPIs (first 6 months, tracked from zero — no prior data exists)

Kept intentionally conservative until real numbers exist to calibrate
against; revise after month 2 once actual conversion data is in.

- Leads per month: 20 (compliance-triggered outreach + content, not paid)
- Conversion rate (lead → paid subscription): unknown until E-07 is fixed
  and at least one real cohort runs through the funnel — do not plan spend
  against last plan's unvalidated 10-15% assumption.
- Real customer case studies published: 2, by month 6 (gates the developer/
  agency channel above)

## Immediate TODOs

- [ ] Confirm E-07 (Stripe Price IDs) is resolved before any paid spend or
      high-volume lead-gen push
- [ ] Build the local Cyber Essentials / compliance-triggered contact list
      (Stornoway + wider Lewis/Harris, plus CE-assessor partnerships)
- [ ] Get 2-3 pilot customers (even at a discount) specifically to generate
      the first real case studies — this unblocks channel #3 entirely
- [ ] Set up Google Ads / analytics tracking before spending on paid channels
- [ ] Confirm VAT treatment / registration status (`marketing/03-pricing-page.md`
      TODO — also blocks confident pricing-page marketing copy)

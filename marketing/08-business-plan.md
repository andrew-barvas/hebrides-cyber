# Hebrides Cyber — Business Plan

## Executive Summary
Hebrides Cyber provides developer-grade security audits and a recurring Security Score product for small businesses, agencies, and SaaS teams. Based in the Isle of Lewis, it combines automated scanning, AI summarisation, and manual testing to deliver actionable remediation. Revenue streams: one-off audits, monthly subscriptions, and white-label services for agencies.

## Problem
Small businesses and many agencies lack affordable, actionable security services. Existing offerings are either too expensive (enterprise firms) or too shallow (automated scanners without human review).

## Solution
A hybrid model: automated Security Score for continuous monitoring, plus manual pen tests and CI/CD hardening for deeper assurance. Developer-friendly reports and remediation support reduce time-to-fix.

## Market
- **Local:** small businesses, tourism operators, churches, charities in the Hebrides and Outer Hebrides.
- **Remote:** small SaaS companies and agencies across the UK and EU.
- **TAM (qualitative):** thousands of small businesses in Scotland; tens of thousands of small SaaS teams in the UK/EU.

## Business Model
- One-off audits: £300–£1,800 per engagement.
- Subscriptions: £20–£75 per month.
- Agency partnerships & white-label: custom pricing.
- Workshops & training: £300+ per session.

## Go-to-Market
- Local outreach + free Security Score lead magnet.
- Content marketing and developer community engagement.
- Paid ads and partnerships with local web agencies.

## Operations
- Lean team: founder + contractor pen testers as needed.
- Automation to scale monthly scans.
- Standardised report and remediation-PR templates to reduce delivery time.

## Financials (first 12 months, conservative)
Assumptions: 20 one-off audits (avg £700) + 40 monthly subscribers (avg £30/mo).

| Item | Amount |
|---|---|
| Audit revenue | £14,000 |
| Subscription revenue | £14,400/year |
| **Total revenue** | **≈ £28,400** |
| Costs (hosting, tools, AI API, marketing, contractors) | £8,000–£12,000 |
| **Net** | Positive from month 6, modest growth |

## Risks & Mitigations
- **Liability from pen tests** → Clear TOS, proof of ownership, scoped engagements, professional indemnity insurance.
- **False positives/negatives in automation** → Combine automated scans with manual review for paid tiers.
- **Competition from larger consultancies** → Focus on speed, price, developer-friendly deliverables, and local trust.

## Roadmap (12 months)
- **Month 0–1:** Launch site, Security Score MVP, local outreach.
- **Month 2–3:** Deliver first audits, iterate report templates, add Stripe billing.
- **Month 4–6:** Launch subscription plans, add Slack alerts, publish case studies.
- **Month 7–12:** Scale via agency partnerships, add white-label features, hire part-time tester.

## Launch Checklist

**Updated 2026-08-28** — this list was still all-unchecked despite the
product being live with paying customers; corrected against actual
current state rather than left stale.

- [ ] Register domain hebridescyber.com — **not yet done**, confirmed via
      DNS lookup 2026-08-28 (non-existent domain); see
      `marketing/10-formalisation-and-funding-roadmap.md` §1 for the full
      domain plan
- [x] Set up GitHub repo and Next.js app
- [x] Provision Supabase (or Azure DB) and Auth
- [x] Implement Security Score scanner (Playwright + dependency checks) —
      grown well beyond the original scope (5 dependency ecosystems,
      secret scanning, container checks, extended active-tool suite)
- [x] Integrate Stripe and billing pages — **but checkout itself is
      currently broken**, `STRIPE_PRICE_BASIC/PRO/AGENCY` unset in
      production (`hebridescyber-app/docs/ENHANCEMENTS.md` E-07,
      highest-priority open item in the whole backlog)
- [x] Create PDF report generator (Playwright)
- [x] Add AI summarisation (Azure OpenAI)
- [x] Build marketing pages and pricing page
- [ ] Get professional indemnity insurance — still open, see
      `hebridescyber-app/docs/ROADMAP.md` BETA-B3
- [x] Start local outreach and run free scans — the product is live and
      taking real signups; see `marketing/06-marketing-plan.md` for the
      current (rewritten) go-to-market plan and its KPIs

For company registration, funding, and certifications — none of which
this original checklist covered — see
`marketing/10-formalisation-and-funding-roadmap.md`.

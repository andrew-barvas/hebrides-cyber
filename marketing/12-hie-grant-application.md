# Highlands and Islands Enterprise — Grant Application

**Draft for owner review. Verify all figures, eligibility criteria, and
deadlines directly with HIE before submission. Nothing below should be
treated as final advice — this is a structured starting point, not a
completed form.**

---

## 1. Applicant Details

| Field | Value |
|---|---|
| Business name | Hebrides Cyber Ltd *(registration in progress — see `marketing/10-formalisation-and-funding-roadmap.md` §2)* |
| Trading address | Stornoway, Isle of Lewis, HS1 |
| Sector | Cybersecurity / Software-as-a-Service |
| Company status | Limited company (to be registered) |
| Founded | 2026 |
| Employees | 1 (founder) |
| Website | hebridescyber.co.uk *(domain registration pending)* |

### Founder Background

The founder brings 15+ years of SecDevOps and cloud delivery experience at
Lockheed Martin and Leidos, plus 15 years in Scottish public-sector digital
transformation delivery. This is not a first-time entrepreneur learning
security — it's an experienced defence-sector professional bringing
enterprise-grade capability to the SME market at an accessible price point.

---

## 2. Project Description

### What Hebrides Cyber does

Hebrides Cyber is an automated security scanning platform that helps UK
small and medium businesses find and fix vulnerabilities in their websites
and web applications. It runs continuous automated security checks —
the same types of tests that large enterprises pay £10,000+ per year for —
and delivers results in plain English with step-by-step fix instructions.

### Current state (September 2026)

The product is **live, deployed, and functional**:

- Deployed on Microsoft Azure, accessible via the web
- 914 automated tests ensuring reliability
- 20 enterprise-grade security features implemented:
  - **Identity & access**: Single Sign-On (SAML), role-based access control,
    SCIM user provisioning, IP allowlisting
  - **Multi-tenancy**: Organisation model, MSP portal for agencies managing
    multiple clients, custom scan policies
  - **Compliance**: Automated reporting across 7 international frameworks
    (ISO 27001, PCI DSS, Cyber Essentials, OWASP Top 10, CIS Controls v8,
    NIS2, DORA)
  - **Integrations**: ServiceNow, Jira, Linear, GitHub Issues, Slack,
    Microsoft Teams, SIEM systems, CI/CD pipelines, GraphQL API
- Continuous Integration/Continuous Deployment pipeline with automated
  quality gates (lint, type checking, unit tests, end-to-end tests)
- Pricing: £20/month (Basic), £35/month (Pro), £75/month (Agency) — 
  5-10x below enterprise alternatives like Qualys or Invicti

### What makes this different

1. **UK compliance-first**: Maps every finding to Cyber Essentials controls
   — the compliance framework UK SMEs actually need, not US-centric
   standards. Also covers ISO 27001, OWASP Top 10, CIS Controls, NIS2,
   and DORA.
2. **Fix-first, not fear-first**: Every finding comes with a four-step
   remediation ladder — plain-English advice, AI-tailored fix for the
   specific tech stack, one-click ticket creation to the dev team, and
   automated pull requests for dependency updates.
3. **Affordable**: A £20/month entry price puts real security scanning
   within reach of any business with a website, not just those with a
   dedicated security budget.
4. **Evidence discipline**: Documented methodology that never reports a
   finding it can't evidence — reduces false positives that waste
   business owners' time and erode trust in security tools.

---

## 3. Local Economic Impact

### Direct benefits to Outer Hebrides businesses

**Free single-page security analysis for qualifying local businesses**:
Hebrides Cyber will provide a free comprehensive security scan and
plain-English report to up to **50 Outer Hebrides businesses in Year 1**.
This covers any local business with a web presence — tourism operators,
trades businesses, churches, charities, community organisations, and
local retailers.

**Discounted subscription rates for Western Isles businesses**: All
businesses registered in the Western Isles (Comhairle nan Eilean Siar
area) will receive a **25% discount** on all subscription plans:
- Basic: £15/month (normally £20)
- Pro: £26/month (normally £35)
- Agency: £56/month (normally £75)

**Free cyber hygiene workshops**: 2-3 free workshops per year for local
businesses, covering topics such as:
- "Is your website secure? A plain-English guide for non-technical
  business owners"
- "Cyber Essentials: what it is, why contracts require it, and how to
  prepare"
- "Protecting your customers' data: practical steps for small businesses"

These could be hosted at An Lanntair, Stornoway Library, or Business
Gateway premises.

### Employment and economic contribution

- **First hire within 12 months**: contractor penetration tester,
  potentially local (subject to CREST qualification pathway)
- **Medium-term (18-24 months)**: support engineer and/or marketing
  assistant — both roles suitable for island-based remote work
- **Export revenue**: 80%+ of projected revenue comes from customers
  outside the islands (UK/EU SaaS companies, digital agencies, SMEs
  needing Cyber Essentials). This brings money **into** the local economy
  from national and international customers
- **Digital skills**: the workshops and free-scan programme raise digital
  security awareness across the local business community, supporting
  the wider digital skills agenda in the Highlands and Islands

### Why the Outer Hebrides specifically

The founder lives and works in Stornoway. This is a genuine island-based
technology business, not a remote office of a mainland company. The
product's Hebrides branding, local-trades landing pages, and
community-benefit programme are integral to the business identity, not
an afterthought.

Island businesses face a particular challenge: they're increasingly
dependent on websites for tourism bookings, online sales, and customer
communication, but have limited access to affordable cybersecurity
expertise. The nearest security consultancy with CREST accreditation
is in Inverness or further — a geography gap this product directly
addresses by making enterprise-grade scanning available as an online
self-service tool.

---

## 4. Funding Request

| Item | Amount | Justification |
|---|---|---|
| Professional indemnity insurance | £1,000 – £2,000/year | Required to offer penetration testing services safely and credibly. Essential for any security business |
| Legal review of Terms of Service | £500 – £1,000 (one-off) | Current ToS is a draft; needs solicitor review before scaling beyond early adopters. A security business needs legally sound terms |
| Domain registration + SSL certificates | £50 – £100 (one-off) | `hebridescyber.com`, `.co.uk`, and defensive registrations |
| CREST CPSA examination + preparation | £1,500 – £2,500 | Industry-recognised penetration testing certification. Enables the founder to offer certified manual testing alongside the automated product |
| Marketing spend (first 6 months) | £2,000 – £3,000 | Google Ads targeting "Cyber Essentials scan UK small business," local press, content marketing. See `marketing/15-launch-campaign.md` for the detailed plan |
| Cloud infrastructure (12 months) | £1,200 – £2,400 | Microsoft Azure hosting, Supabase database, Sentry error tracking, Resend email service, Upstash rate limiting |
| **Total** | **£6,250 – £11,000** | |

All items are directly tied to making the business operational and
revenue-generating. There is no speculative R&D in this request — the
product is already built and deployed.

---

## 5. Commercial Viability

### Revenue projections (conservative)

From `marketing/08-business-plan.md`:

| Metric | Year 1 | Year 2 |
|---|---|---|
| Target customers | 50 | 150 |
| Average revenue per customer | £568/year | £568/year |
| **Projected revenue** | **£28,400** | **£85,200** |
| Operating costs | £8,000 – £12,000 | £15,000 – £20,000 |
| **Projected profit** | **£16,400 – £20,400** | **£65,200 – £70,200** |

### Path to profitability

- **Break-even**: approximately 15-20 paying customers (achievable within
  3-4 months of launch with the marketing plan in place)
- **Payback on grant funding**: the grant funds operational costs that
  would otherwise come from personal savings; revenue begins from month 1
  of marketing launch
- **Recurring revenue model**: SaaS subscriptions provide predictable
  monthly income, not project-based feast-or-famine

### Competitive position

The product occupies a genuinely underserved market position: **enterprise
security scanning at SME prices, with UK compliance framing.** Direct
competitors either:
- Charge 5-10x more (Qualys, Invicti, Rapid7)
- Don't serve the UK compliance market (StackHawk, Beagle Security —
  US-focused)
- Don't offer the same depth (Intruder, Probely — fewer enterprise
  features at similar prices)

See `docs/COMPETITIVE-ANALYSIS.md` for the detailed competitive
positioning with evidence.

---

## 6. Supporting Evidence

Available on request or attached to this application:

1. **Live product demonstration** — the product is deployed and functional;
   a live demo can be arranged at any time
2. **Functionality matrix** (`docs/FUNCTIONALITY-MATRIX.md`) — code-verified
   feature inventory showing every capability, how it's implemented, and
   how it's tested
3. **Competitive analysis** (`docs/COMPETITIVE-ANALYSIS.md`) — 12-dimension
   scoring rubric with evidence-backed positioning against 7 direct
   competitors
4. **Test suite results** — 914 automated tests with continuous integration;
   the product's own engineering discipline exceeds what most funded
   startups demonstrate
5. **Use cases** (`docs/USE-CASES.md`) — 6 concrete customer scenarios
   including specific Outer Hebrides business types (tourism, trades,
   churches)
6. **Business plan** (`marketing/08-business-plan.md`) — full financial
   model with conservative assumptions

---

## 7. Alignment with HIE Strategic Priorities

- **Digital economy development**: a technology product built in and
  exported from the Highlands and Islands
- **Business start-up support**: a genuine new venture with a viable
  commercial model, not a lifestyle project
- **Community resilience**: raising digital security standards for local
  businesses protects customers, visitors, and the local economy from
  cyber incidents
- **Skills and employment**: creating technology employment opportunities
  in the Western Isles, with planned workshops to raise local digital
  skills
- **Export growth**: 80%+ of revenue from outside the region, bringing
  income into the islands

---

## 8. Timeline

| Month | Milestone |
|---|---|
| 1 | Company registration, domain live, insurance secured |
| 2 | Marketing launch, social media active, first 10 free local scans |
| 3 | First paying customers, CREST CPSA exam booked |
| 4-6 | 20+ paying customers, first workshop delivered, grant impact report |
| 7-12 | 50+ customers, first hire planned, expanded feature set (SBOM, EASM) |

---

*This application was prepared by the founder using the product's own
documentation as evidence. All technical claims are verifiable against
the codebase and test suite. All financial projections are from
`marketing/08-business-plan.md` and are deliberately conservative.*

# Formalisation & Funding Roadmap

Covers the four things `marketing/08-business-plan.md` doesn't: securing a
real domain, formal company registration, external funding (Highlands and
Islands Enterprise or similar), and the founder's own certification path.
Everything here is a **draft for the account owner's judgement** — company
registration and funding applications carry real legal/financial weight
Claude Code cannot and should not decide on the owner's behalf. Verify every
figure, deadline, and eligibility rule directly with the named body before
acting on it; nothing below should be treated as final advice.

---

## 1. Domain

**Checked 2026-08-28**: `hebridescyber.com` — the domain every marketing
document and the branding guide (`marketing/02-branding.md`) already
assumes — is **not registered** (DNS: non-existent domain), and the live
Static Web App has no custom hostname configured at all
(`az staticwebapp hostname list` returns empty; the app is only reachable at
`proud-stone-04a76350f.7.azurestaticapps.net`). This isn't a rebrand
decision, it's finishing a step the business plan's own launch checklist
already called out and never ticked off.

### Options, in order of what to actually do

1. **Register `hebridescyber.com` (and `.co.uk`) now, regardless of what
   else happens below.** This is the domain every piece of existing copy
   already assumes; not registering it is the single most avoidable gap.
   Register both the `.com` and `.co.uk` — cheap insurance against someone
   else taking the other one, and `.co.uk` reads as more locally credible
   to a UK SME buyer.
2. **`hebcyber.com`/`.co.uk`** — shorter, worth registering defensively
   (redirect to the main domain) even if not the primary brand, so a
   competitor or squatter can't use the near-identical short form.
3. **`cyber@hebrides.com`/`.co.uk` via your uncle's domain** — genuinely
   useful as a *secondary* email address (the Hebrides association is a
   real trust signal for local outreach specifically), but not as the
   primary domain. Reasons not to build the whole brand on it:
   - It's someone else's asset — if his mussel farm business changes hands,
     folds, or the domain lapses, the security business's email and any
     links pointing at it break with zero warning and no ability to fix it
     unilaterally.
   - A funding body or company-registration reviewer (see §3 below) will
     look more favourably on a business that owns its own domain
     outright — it signals the venture is a real, independent entity, not
     riding on a family member's infrastructure.
   - It costs nothing to ask, though: a `cyber@hebrides.co.uk` forwarding
     address alongside the real `hebridescyber.com`/`.co.uk` domains is a
     nice-to-have add-on for local credibility, not a replacement.

**Recommended action**: register `hebridescyber.com` + `.co.uk` and
`hebcyber.com` + `.co.uk` this week (a registrar checkout, a few minutes,
low cost); ask your uncle about the `cyber@hebrides.co.uk` forwarding
address as a bonus, not a dependency. Once `hebridescyber.com` is live,
point the Static Web App's custom domain at it and update
`NEXT_PUBLIC_SITE_URL` — both real, small follow-up tasks once you've
actually bought it (not done here, since I can't purchase a domain on your
behalf — see the "Prohibited" actions Claude Code follows).

---

## 2. Company registration (UK)

Operating as a sole trader vs. registering a limited company is a real
financial/liability decision, not a technical one — the summary below is
general orientation, not tax or legal advice; confirm with an accountant
before filing anything.

### Why a limited company is very likely worth it here specifically

- **This product runs active security tests against third-party
  infrastructure** (nmap, nuclei, sqlmap, XSSer, commix — per
  `hebridescyber-app/docs/security.md`). A limited company's liability
  shield is genuinely relevant for this kind of work in a way it wouldn't
  be for, say, a simple content business.
- **Funding bodies (§3) overwhelmingly prefer or require a registered
  company** over a sole trader when awarding grants — this is usually a
  hard eligibility gate, not a preference, for HIE-style funding.
- **Client trust**: SME buyers evaluating a security vendor look for
  "Limited" in the name as a basic credibility signal.

### The mechanics (England/Wales/Scotland all use Companies House — no
Scotland-specific registration body)

1. Choose a company name (check availability at Companies House first —
   confirm `Hebrides Cyber Ltd` or similar isn't already taken).
2. Register at [Companies House](https://www.gov.uk/limited-company-formation)
   — online registration is typically same-day, costs a small statutory fee
   (check the current fee on GOV.UK directly, it changes).
3. Appoint at least one director (you) and decide on shareholding (100%
   yourself is the simplest starting structure for a solo founder).
4. Register for Corporation Tax with HMRC within 3 months of starting to
   trade (a GOV.UK online step, separate from Companies House
   registration).
5. Decide VAT registration timing — `marketing/03-pricing-page.md`'s own
   TODO already flags this as unresolved; the VAT registration threshold
   is published on GOV.UK and changes periodically, check the current
   figure before treating current pricing as VAT-inclusive or -exclusive.
6. Open a business bank account in the company's name — most UK banks now
   support fully digital onboarding for a new Ltd company.
7. Consider a company secretary/accountant for annual accounts and
   Confirmation Statement filings (a legal minimum, not optional, once
   registered) — a fixed monthly-fee online accountant (several UK
   providers specialise in solo-founder Ltd companies) is the common,
   affordable route rather than a traditional accountancy firm.

### SIC code

Pick a Standard Industrial Classification code that matches what the
business actually does — likely something in the "Computer programming,
consultancy" or "Information security" family. Confirm the exact current
code list on Companies House at registration time rather than assuming a
code here, since SIC lists are revised periodically.

**Working draft for the registration form** (non-personal details only —
confirm each with your accountant or against the live Companies House
form before submitting):

| Field | Draft value |
|---|---|
| Company name | Hebrides Cyber Ltd (check availability first) |
| Company type | Private company limited by shares |
| Primary SIC | 62020 — Information technology consultancy activities |
| Optional second SIC | 62012 — Business and domestic software development |
| Share capital | Ordinary shares, GBP 1 nominal; a small number such as 100 or 1,000 is common for a solo founder, and a statement of capital is required at incorporation |
| Articles | Model articles |
| Registered office | Must be a real address where documents can be delivered. A service or accountant address can be used instead of your home address, which is public on the register |

**Personal details are not kept in this repository.** Director name, date
of birth, home and service addresses, nationality and any person with
significant control are entered directly on the Companies House form.
Check Companies House's current guidance on what appears on the public
register (a director's month and year of birth are normally public; a home
address is kept off it when a service address is given).

---

## 3. Funding: Highlands and Islands Enterprise and other Scottish bodies

**Highlands and Islands Enterprise (HIE)** is the right primary target —
it's the actual devolved economic development agency for this region
specifically (Scottish Enterprise, the mainland-Scotland equivalent, does
not cover the Highlands and Islands — HIE is the correct body, not a
second choice). Beyond HIE, worth researching in parallel (real bodies,
not exhaustively verified here — confirm current schemes/eligibility
directly with each):

- **Point and Sandwick Trust** — the Isle of Lewis community trust funded
  by the Beinn Ghrideag wind farm, which funds local business and
  community projects specifically in Point and the wider Lewis area. Worth
  checking eligibility given the business's actual location.
- **Comhairle nan Eilean Siar** (Western Isles Council) — local authority
  business-support grants, worth checking alongside HIE.
- **Business Gateway Scotland** — free business advice and a common first
  stop before a grant application; can help sanity-check the business
  case below before it goes to HIE.
- **Scotland's Cyber Resilience Strategy / Cyber Growth Partnership** —
  Scottish Government's own cyber-sector growth initiative; worth checking
  whether it has a grants or accelerator arm the business qualifies for,
  given this venture is literally in-sector.
- **Innovate UK** — UK-wide (not Scotland-specific), relevant if any part
  of the roadmap (e.g. the fleet dashboard/compliance-trend reporting work
  already in `hebridescyber-app/docs/SPRINT-PLAN.md`) could be framed as
  R&D/innovation rather than pure commercial delivery — Innovate UK grants
  are typically easier to win with a genuine technical-innovation angle.

### Draft business case outline (for a HIE-style application)

Grounded in what's actually true about the business today, per this
session's own audit work — not aspirational claims:

**1. What the business does today (already real, not a pitch)**
Hebrides Cyber is a live, operating security-scanning SaaS product with
paying customers on Stripe, an automated scanning pipeline (TLS, headers,
dependency CVEs across 5 ecosystems, secret scanning, container security),
a remediation-PR feature that few competitors at this price point offer,
and UK Cyber Essentials compliance mapping. Point to
`hebridescyber-app/docs/FUNCTIONALITY-MATRIX.md` and
`hebridescyber-app/docs/COMPETITIVE-ANALYSIS.md` for the evidence-checked
detail — a funding reviewer will take a specific, code-verified capability
list far more seriously than generic marketing claims.

**2. The local-community case (HIE cares about this specifically)**
- **Digital resilience for island SMEs**: tourism operators, crofters,
  and local trades in the Outer Hebrides are exactly the underserved
  segment `hebridescyber-app/docs/COMPETITIVE-ANALYSIS.md` identifies —
  affordable security is otherwise inaccessible to them (too expensive
  from mainland/national consultancies, too shallow from generic
  automated-only tools).
- **Jobs and skills retention in the islands**: a growing, funded venture
  supports the case for hiring locally (even one contractor pen tester,
  per `marketing/08-business-plan.md`'s own operations plan) — keeps
  technical work and revenue in the islands rather than exporting it to a
  mainland or overseas firm.
- **Digital economy diversification**: cyber security is a genuinely
  location-independent export sector — the business already serves remote
  UK/EU customers (per its own market analysis), meaning HIE funding here
  supports export-earning digital-economy growth, not just a local-service
  business, which is usually a stronger case for this kind of body.

**3. The enterprise-grade case (why this isn't just a local lifestyle
business)**
- Real, disclosed technical differentiation (New/Fixed diffing, the
  remediation-PR ladder, CI-gated builds) that competes credibly against
  funded, VC-backed competitors like Intruder.io and Detectify — this is
  a genuine growth business, not a subsistence one, which matters for a
  funding body assessing scalability.
- A clear-eyed, evidence-based roadmap (this repo's own
  `docs/ROADMAP.md`/`docs/ENHANCEMENTS.md`/`docs/SPRINT-PLAN.md`) rather
  than a vague pitch-deck plan — worth showing directly if the application
  format allows supporting technical documentation.

**4. What funding would actually be used for** — be specific, not vague,
when this section is actually written: e.g. professional indemnity
insurance and legal review (already flagged as an open gap in
`hebridescyber-app/docs/ROADMAP.md` BETA-B3), the first contractor pen
tester hire, marketing spend once the funnel is proven (E-07 fixed and a
real conversion rate measured, per `marketing/06-marketing-plan.md`), and/
or the certifications in §4 below.

**Before submitting anything**: get the actual current application
process, forms, deadlines, and funding bands directly from HIE's own
site/an adviser call — don't treat any figure in this document as current,
since none were sourced from a live HIE page.

---

## 4. Certifications, courses, and funded-training routes

Chosen for relevance to a solo UK security-consultancy founder whose
product already leans on Cyber Essentials/compliance framing — not a
generic "every security cert" list. Roughly in priority order:

### Directly reinforces the existing product positioning
- **IASME Cyber Essentials Certified Assessor** status — since Cyber
  Essentials mapping is already a genuine product differentiator
  (`docs/COMPETITIVE-ANALYSIS.md` §5), becoming an accredited assessor
  yourself would let the business *certify* clients, not just report
  against the framework — a real, sellable service extension.
- **ISO/IEC 27001 Lead Implementer** (or Lead Auditor) — directly useful
  advising the SME clients this business already targets, many of whom
  will eventually need this for their own procurement/insurance
  requirements.

### UK-recognised penetration-testing credentials (needed for credible
manual testing, and for CHECK-scheme government work specifically)
- **CREST CPSA** (Practitioner Security Analyst) then **CRT** (Registered
  Tester) — the standard UK industry-recognised path; CREST accreditation
  is what most UK enterprise/public-sector clients actually ask for when
  procuring a pen test, and is a prerequisite route toward NCSC's CHECK
  scheme if government-sector work is ever a target.

### Globally-recognised, hands-on technical credentials
- **CompTIA Security+** — a solid, quick foundational credential if
  nothing formal exists yet; useful as a first step and widely recognised
  by non-technical buyers.
- **OSCP** (Offensive Security Certified Professional) — the
  globally-respected, genuinely hands-on pen-testing credential; harder
  and more expensive than the above, but carries real weight with
  technical buyers and agencies.

### Cloud-specific (matches the Azure-heavy stack this product already
runs on)
- **Microsoft Certified: Security, Compliance, and Identity Fundamentals**
  (SC-900) as an entry point, then **Azure Security Engineer Associate**
  (SC-200 or AZ-500 depending on current Microsoft naming — verify the
  current exam code, Microsoft renames these periodically) — directly
  relevant given the product's own Azure Container Apps/Static Web Apps
  infrastructure.

### Funded/free routes worth checking before paying full price
- **Skills Development Scotland** — check for funded routes or individual
  training accounts that cover part of the above.
- **HIE's own business-support grants** may cover training/certification
  costs specifically — worth asking directly whether a HIE grant (§3) can
  include a training-cost line, rather than treating funding and
  certification as two separate asks.
- **NCSC CyberFirst** — UK-government-backed, sometimes has funded
  routes for those already working in the sector, not just students.

**Sequencing suggestion**: don't try to do all of this at once. The IASME
assessor route and CREST CPSA most directly reinforce revenue the business
can already generate; the cloud certifications are cheap and quick wins;
OSCP is the highest-effort item and worth scheduling only once the
business has steadier cash flow (ties back to §3's funding case, and to
`marketing/06-marketing-plan.md`'s own KPI targets).
